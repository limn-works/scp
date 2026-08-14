---
name: scp-out-039-c12-sdk-gap-detection
description: SCP-OUT-039 C12 delta (feat/outlet-streaming-ffi) — SDK-layer receiver gap-detection premise interrogated; locus-siting premature/incoherent
metadata:
  type: project
---

# SCP-OUT-039 C12: receiver gap-detection in 4 SDK drains

Interrogated `git diff b3a1dd3dc..9c63e91b2` in worktree scp-wt-ffi. Verdict: INTERROGATE FURTHER — behavior is fail-closed/harmless, but the DECISION-SITING is premature and incoherent with the same PR.

**Why:** D3 ships PRODUCTION gap-detection (a new `StreamGap`/6131 error + `_expected_sequence` cursor + `_send_cancel` refactor) in all 4 SDK InvocationHandle drains, justified as defense-in-depth "mirroring the §5.4.5 revocation-recheck posture." Two premise failures found:
1. **Analogy is asymmetric on the load-bearing axis.** Spec line 517 sites the revocation recheck EXPLICITLY at the SDK framework ("the stream receiver's SDK framework MUST") AND it has a live same-context trigger (revocation is transport-independent). Spec line 513 (gap) says only "a receiver" — no SDK-locus mandate — and has NO same-context trigger (pump renumbers next_seq 0,1,2… at dispatch.rs:2729/3064, so the drain provably never sees a gap same-context). Borrowing the receiver-side-SDK form where its justification (spec-mandated locus + live trigger) does not transfer = cargo-cult.
2. **Same-PR incoherence / artifact-flow inversion.** The Rust harness `ReceiverSequenceTracker` (outlet_stream_vectors_common.rs:383) is labeled TEST-ONLY, with the production detector deferred to slice 3 ("when the slice-3 transport gap path lands, the production detector replaces the tracker" — also in spec §25.21). So the Rust-layer decision is "defer production detection to slice 3, validate with a test tracker now"; the SDK-layer decision is the OPPOSITE ("ship production now"). A test-vector story (SCP-OUT-039, charter = author vectors) is siting a production receiver-architecture decision that belongs to ADR-061/§5.4.5/slice-3. If slice-3 sites the authoritative detector at the Rust receiver (as the doc implies), the 4 SDK checks become redundant runtime re-checks of an upstream-enforced property (CLAUDE.md non-convergent-enforcement negative-value pattern) — or DOA. The gap vector is ALREADY validated at the Rust tracker across all 6 tiers, so the SDK drains add per-language coverage contingent on the unresolved slice-3 locus decision.

**How to apply:** Honest path = validate sequence_gap at the Rust receiver-tracker now (already done 6 ways); defer the production receiver detector to slice-3 where it has a live trigger + authoritative home; decide the locus (Rust receiver vs SDK vs both) in the ADR/spec FIRST, then let the vector story validate it. Distinguish: SDK per-chunk SIGNATURE verify = warranted (cryptographic equivocation root, §5.4.5:481); SDK sequence-MONOTONICITY re-check = redundant once a sound upstream detector exists.

## Secondary findings
- QUESTION (MED): `credit_exhaustion` vector named after the WRONG failure mode — it tests credit-STALL (no grant → stall → 6133/execution.credit-stall/WithBackoff), but there is a real distinct slug `execution.credit-exhausted` (6131/Immediate). Honest name = `credit_stall`. Story dismissed only the wrong "fix" (change slug to 6131), never the right one (rename vector). Name AC-locked (AC1). Documented as a "trap" but self-inflicted + avoidable.
- QUESTION (LOW, pre-existing round-8): code 6131 is triple-slugged (credit-exhausted / stream-gap / stream-cap-exhausted) and error_code_to_retry_policy keys on CODE → all three get RetryPolicy::Immediate (error_codes.rs:573). stream-cap-exhausted = node-pump-ceiling saturation, for which Immediate retry is wrong backpressure. Not introduced by this diff.
