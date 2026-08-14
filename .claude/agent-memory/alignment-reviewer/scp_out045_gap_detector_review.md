---
name: scp-out045-gap-detector-review
description: SCP-OUT-045 cross-context reassembly gap-detector review (2026-07-16) — MISALIGNED, scar-tissue BLOCKER (base_sequence tautology + phantom 047 lossy-relay citation)
metadata:
  type: project
---

# SCP-OUT-045 gap-detector review @ 942a33d22 (2026-07-16) — MISALIGNED

Branch feat/outlet-xctx-045-gap-detector. Commit touches only .docs/prds/outlet.json + crates/scp-runtime/src/context/outlets/invoke.rs.

**Why (verdict): scar-tissue BLOCKER.** The `ReassemblyGapDetector` keys on `base_sequence` — the per-sender anchor that SCP-OUT-044 allocates LOCALLY at consumption on the bridge send hop (`forward_frame` → `SequenceReservation::reserve`, invoke.rs:4516), strictly `+1` by construction. So `gap_detector.observe()` (invoke.rs:4985) is tautologically `Contiguous` in production — it checks the bridge's own send counter against an identical expectation counter. The ONLY thing that makes it return `Gap` is the TEST-ONLY `ObservedBaseSequenceProbe` (`None` on the sole production call site invoke.rs:5741). A dropped frame on the real (inner B→bridge) hop gaps `chunk.sequence` (operator index), NOT base_sequence (bridge re-allocates contiguous anchors to survivors). Detector is structurally incapable of observing real transport loss on either hop → violates no-test-stand-in tenet + redundant-self-check (simplifier BLOCKER class).

**Phantom citation:** code/comments/AC repeatedly cite "the SCP-OUT-047 lossy relay" (invoke.rs:4457,4803,4980,5759,9112,9123) as what makes it load-bearing. SCP-OUT-047 is actually "Streaming-saga FFI surface across 4 bridges" — NOT a lossy relay. No PRD story introduces a relay-provided base_sequence. Internal contradiction: 4341/4457 say 047 makes base_sequence relay-provided; 4386-4391 say 047's re-seal assigns its OWN send-seq and base_sequence is never fed there.

**Spec drift:** `base_sequence` appears 0 times in .docs/specs/05-contexts.md. Spec §5.4.5:513/:515 defines a gap as a missing `sequence`. AC1 "keys on (request_id, base_sequence)" silently reinterprets the spec's `sequence` onto a code-convenient local anchor — artifact-flow inversion (impl detail → story/spec-reading).

**What PASSES:** (a) dual-locus cancel-split IS spec-faithful — §5.4.5:515 attributes the signed OutletCancel to the SDK-drain InvocationHandle, and the bridge genuinely has no signer (no signer param in run_cross_context_bridge sig), so runtime-surfaces-terminal + SDK-drain-mints-signed-cancel matches spec attribution and does NOT weaken the MUST (gap still closes both hops). (b) Spec NOT modified (one-way flow preserved). (c) 6131 shared code (execution.credit-exhausted/stream-gap/stream-cap all share CODE_EXECUTION_CREDIT per error_codes.rs:36) + SLUG_EXECUTION_STREAM_GAP correct. (d) ReceiverSequenceTracker untouched.

**Fix recommendation:** key the bridge-level detector on `chunk.sequence` (already read at invoke.rs:4966) — spec's own gap key, genuinely dormant-but-load-bearing (fires on real inner-hop loss with no rewire, no test seam), matching the revocation dual-locus analogy (same property, two layers). Then delete the ObservedBaseSequenceProbe seam and the 047-lossy-relay citations.

**Reusable pattern:** a "gap detector" keyed on a counter the same component allocates monotonically is a tautology, not defense-in-depth. Check whether the detector observes a value that can actually diverge from its own expectation on a real path — if the only divergence source is a test seam, it's a stub dressed as wired.
