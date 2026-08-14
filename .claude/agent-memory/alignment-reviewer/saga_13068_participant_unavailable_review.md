---
name: saga-13068-participant-unavailable-review
description: Review of SCP-SAGA-13068 ParticipantUnavailable taxonomy add (saga-121); found FFI bridge-export # Errors doc layer skipped
metadata:
  type: project
---

# §6.2.4 saga `ParticipantUnavailable` / SCP-SAGA-13068 (branch fix/121-mailbox-saturated-saga-terminal, HEAD ba1ed1eec)

Change: transient Prepare-phase `ContextError::ActorBusy` typed as new fieldless `SagaAbortReason::ParticipantUnavailable`, code 13068, retryable. Lift `lift_run_saga_error` matches `ContextError::ActorBusy(_) => (ParticipantUnavailable, 13068)` BEFORE RateLimited/`_`, AFTER the `needs_repair` short-circuit (commit-phase ActorBusy → NeedsRepair, pinned by test). 13068 synthesized (ActorBusy is codeless). Classification code + tests are correct and well-tested (e2e closed-mailbox + 2 lift unit tests). Honest reachability verified against `actor/handle.rs:130-143`: three real ActorBusy producers (full-for-SEND_TIMEOUT, inbox-closed, reply-dropped-after-process); transiently-full-but-open races phase timeout (SEND_TIMEOUT==PHASE_TIMEOUT) — acknowledged in ADR/spec/variant-rustdoc.

**Verdict: code + artifacts ALIGNED, ONE residual cross-layer doc inconsistency.**

**Finding (reusable):** The reframe updated core rustdoc + FFI-common `saga_errors.rs` (classification home) + all 4 SDK wrappers — but SKIPPED the FFI **bridge-export** `# Errors` doc-comments, a distinct doc layer sitting BETWEEN core and SDK wrappers. Stale sites still say "a Prepare-phase rejection — authorization, freshness, rate limit, or co-residency" (omit ParticipantUnavailable, keep "rejection" not "abort"):
- `crates/scp-ffi/src/tools.rs:1921` (PyO3)
- `crates/scp-ffi/uniffi/src/bridge.rs:12304` (UniFFI)
- `crates/scp-ffi/napi/src/scp.rs:2925` (NAPI)
- `bindings/swift/Sources/SCP/Internal/ScpBindings.swift:3118 & :6148` (generated from UniFFI — fixes on regen)
No bridge mentions ParticipantUnavailable. WASM N/A (no Supervisor, ADR-034).

**Pattern:** when reframing a saga/error taxonomy, the per-export bridge `# Errors` rustdoc (pyo3 tools.rs / uniffi bridge.rs / napi scp.rs) + generated `ScpBindings.swift` are their OWN layer — grep every bridge for the OLD cause-enumeration string ("authorization, freshness, rate limit, or co-residency" — note it WRAPS across `///` lines so a contiguous-string grep misses pyo3/uniffi; grep "Prepare-phase rejection" too).

Non-findings: supervisor.rs:446 "Prepare-phase rejection" is the `Rejected` VARIANT rustdoc (correct). saga.rs:50 handler-band "Prepare-phase rejections … SCP-SAGA-13xxx codes" is defensible (handler emits only coded rejects, not codeless ActorBusy). Registry 13068 in-band 13000-13999, supervisor sub-band 13050-13099 (sdk-common.md:67), sequential after 13067.
