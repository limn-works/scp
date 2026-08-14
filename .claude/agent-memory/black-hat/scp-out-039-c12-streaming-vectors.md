---
name: scp-out-039-c12-streaming-vectors
description: BLACK-hat on SCP-OUT-039 C12 (feat/outlet-streaming-ffi, diff b3a1dd3dc..9c63e91b2) — SDK receiver gap-detection in 4 drains + outlet-streaming conformance vectors + test-grant feature seam. VERDICT could not break; clean.
metadata:
  type: project
---

# SCP-OUT-039 C12 @9c63e91b2 (feat/outlet-streaming-ffi) — COULD NOT BREAK

Diff = SDK half: receiver sequence-gap detection in 4 SDK drains (py/ts/swift/kotlin) + WASM
pure-wrapper vector test + FFI/scp-testing conformance vector wiring + Cargo feature FORWARDING.
Runtime seam files (commands.rs/messaging.rs/supervisor.rs TestGrant*) NOT in diff — pre-existing.

## Gap-detection (the new receiver logic) — SOUND, symmetric across all 4 SDKs
- expectedSequence starts 0; chunk.sequence != expected → closed=true, capture StreamGap(6131),
  best-effort sendCancel (same signed bridge path as public cancel), throw. Gap check runs BEFORE
  terminal check and BEFORE increment → a wrong-seq forged End is a gap, not a premature terminal.
- Q1(a) DoS livelock: NO. SDK cancels ONCE + marks closed; ZERO auto-retry in InvocationHandle or
  above (Context/SCP). 1 dropped chunk → 1 cancel + terminal StreamGap. Rerun = consumer policy,
  identical to any lossy channel; a MITM relay already has drop power. No amplification.
- Q1(b) forced-cancel weaponization: LIMITED to DoS-of-own-stream the MITM relay already possesses.
  SDK cancel passes ONLY (handle_id, caller_did) — never a next_seq or caveats_binding. Injected
  chunk's sequence is used ONLY in the error-message STRING, never forwarded. Bridge signs cancel
  under invoker custody key at runtime-DERIVED cursor. Not weaponizable.
- Q1(c) billing corruption via cancel_ack_seq: NO. cancel_ack_seq is set by the EXECUTOR in its
  signed cancel-ack, not by invoker/SDK. SDK cancel carries no seq. Injected seq never reaches billing.
- Q2 malicious-executor over-bill/stall: SDK has NO gap tolerance (cancels on any gap) → no phantom-
  seq-jump over-bill. Credit-stall 6133 is a runtime-enforced framework terminal; billing runtime-
  computed, NOT in this SDK diff. SDK just surfaces terminals faithfully. Grants invoker-initiated +
  Credit-validated [1,2^32). No SDK-side exploit.
- StreamGap modeled as Protocol-class SDK exception but carries Execution-class code 6131 — intentional
  + documented, consistent all 4 SDKs. Non-issue.

## Test-grant feature seam + RFC operator key — NO PROD LEAK (two layers)
- `outlet-capability-test-grant` = leaf `[]` in scp-runtime; forwarded ONLY via explicit chains
  (core→runtime, ffi/uniffi/napi→core). NOT implied by testing / default / allow_in_memory_custody
  (deliberate — comment: testing leaks into every custody bridge build; escalation must not).
- TestGrantMemberCapability variant + dispatch + handler + Supervisor::test_grant_member_capability
  ALL `#[cfg(feature="outlet-capability-test-grant")]`, AND zero FFI/SDK export → even --all-features
  compiles the primitive but nothing calls it from any public surface. Precedent: saga-witness-test-mint.
- All test_grant_member_capability callers are tests/ dir or #[cfg(test)]. RFC 8032 §7.1 Test1 seed
  (0x9d61…7f60) appears only in: scp-client-wasm/src/lib.rs (#[cfg(test)] mod pure_wrapper_tests),
  napi/src/outlet_stream/tests.rs (#[cfg(test)] mod tests confirmed at outlet_stream.rs:1045), and 4
  tests/ files. Never a shipped binary.

## Spec §25.2 pubkey change = a FIX not phantom provenance
- Old display `…daa3f4a18446b0b8d183f8e3` was a wrong transcription; new `…daa62325af021a68f707511a`
  is the true RFC 8032 §7.1 Test1 pubkey. REF_PUBKEY (test_vectors.rs:42) + WASM EXPECTED_OPERATOR_PK
  ALREADY held the correct value. No expected-output hash pinned on old value. Removes a divergence.
- §25.21 honest: documents bridge single-shot handler deferral (multi_chunk/error_recoverable/
  credit_exhaustion covered at runtime tier), and that gap detection is defense-in-depth for a
  transport-gap trigger that doesn't exist yet (slice-3 future). No phantom provenance.

## Only LOW note (defense-in-depth, matches precedent, NOT a blocker)
- No mechanical gate stops a future build config adding outlet-capability-test-grant to a shipped
  feature set. Protection is correct-by-construction (not enabled anywhere shipped + no FFI export +
  double-layer so --all-features is inert). saga-witness-test-mint has no gate either. Acceptable.
