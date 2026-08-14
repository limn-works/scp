---
name: outlet-stream-c12-gap-detection
description: C12 SDK receiver sequence-gap detection review (feat/outlet-streaming-ffi 9c63e91b2) — CLEAN, zero blocking
metadata:
  type: project
---

# Outlet-streaming C12 SDK gap-detection (feat/outlet-streaming-ffi a357c94f1/9c63e91b2) -- 2026-07-14 -- CLEAN, ZERO BLOCKING (1 LOW non-security)

Diff b3a1dd3dc..9c63e91b2. New receiver-side §5.4.5 gap detection in all 4 InvocationHandle drains (Python/TS/Swift/Kotlin) + conformance vectors + Rust harnesses. WASM = TEST-ONLY (no runtime, no drain; wire-integrity KAT only).

**Why reviewed clean:**
- Gap path sets `closed=true` BEFORE the best-effort cancel await in ALL 4 SDKs → no re-open window, no double-fire (concurrent public cancel/grantCredit see closed → StreamAlreadyClosed). One cancel per gap, no auto-rerun → no amplification.
- Cancel routes through the identical `_send_cancel`/`sendCancel` → bridge `outlet_stream_cancel(handle_id, params.caller_did)`. Same signed, caller-principal-bound path as public cancel (CRITICAL#1 §5.4.5). caller_did is the invoker's own DID, not attacker-influenced → no new authority / confused-deputy.
- Cancel-send error swallowed (try/except pass, try?, runCatching, catch{}) but terminal StreamGap always raised; stream stays closed. Fail-safe.
- Sticky terminal: re-aggregate re-raises stored gap (Python `_error`, TS `#error`, Swift `streamGapError`, Kotlin `streamGapError` prioritized over terminalError). Control-plane guarded post-gap.
- expectedSequence 0-start + `+=1` EXACTLY matches runtime: invoke.rs:3540 `sequence:u64=0`, outlets_helpers.rs:3176 `saturating_add(1)`, stream.rs:450 "starting at 0". No false-gap on production streams.
- Single-drain guard present per SDK: Python `_draining` bool, TS `#draining` bool, Swift actor + `draining`, Kotlin AtomicBoolean CAS. Gap check ordered before terminal check → gapped End is rejected not aggregated (can't trust End after a hole); regression (replay) also trips gap.
- `sequence` (8B BE) is INSIDE the signed chunk preimage (stream.rs:502, compute_chunk_sig_preimage). Relay cannot forge/mask a gap without breaking the operator sig (verified before SDK). Only bounded drop/reorder → cancel-and-rerun = the intended §5.4.5 mitigation, no SDK amplification.
- Key material: REFERENCE_OPERATOR_SEED = RFC 8032 §7.1 Test Vector 1 (public), pinned against EXPECTED_OPERATOR_PK d75a9801… Public test key, NOT real. caveats_binding values are SHA-256 KATs.
- StreamGap type: ProtocolError→OutletError in all SDKs so `_error:OutletError` assignment typechecks; code SCP-OUTLET-6131 = canonical CODE_EXECUTION_CREDIT (shared execution.stream-gap slug).

**LOW (non-security, a357c94f1 vectors):** `credit_exhaustion` vector maps to SCP-OUTLET-6133 (=credit-STALL) not 6131 (=credit-exhausted). Name vs code mismatch; harmless (smoke test just round-trips the bridge-delivered code) but imprecise. Possibly intentional (models a stall terminal). Not gap-detection code.
