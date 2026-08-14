---
name: eventlog-pseudonym-removal-f438acf0f
description: Phase-2 substrate follow-up — removed EventType::PseudonymAnnounced (76→75 variants) as non-convergent receive-path event; APPROVE w/ 1 stale spec prose
metadata:
  type: project
---

PseudonymAnnounced removal review @ HEAD `f438acf0f` (branch `feat/eventlog-unification-phase2-substrate`), base `1c0ccbc7d`. Two commits: `96f46eeeb` (ADR-011 amendment in phase-2.md) PRECEDES `f438acf0f` (code) — artifact-flow correct.

**Why:** Durable receive-path Merkle append of PseudonymAnnounced was non-convergent (per-receiver arrival order; late joiners miss earlier announcements; WASM never appends on receive) → divergent tree::root would false-positive §9.9.3 equivocation detection. Same class as MessageReceived + EquivocationDetected (already ContextEvent-only). Zero durable consumers (no checkpoint/export/proof reads it). Real purpose = §9.10.4 routing bootstrap, carried entirely by in-memory registry insert + `ContextEvent::PseudonymAnnounced` buffer signal (both KEPT).

**Verified ALIGNED (APPROVE):**
- ADR amendment internally consistent: "two exclusions"→"three exclusions" updated throughout; PseudonymAnnounced documented as §9.10.4 ContextEvent-only signal alongside MessageReceived/EquivocationDetected; variant comment at phase-2.md:807 replaced with NOT-durable note.
- §9.10 correctly dropped from unification-group source comment (`§19/§5.11A/§9.9/§9.10`→`§19/§5.11A/§9.9`) in BOTH phase-2.md:782 and lib.rs:225 — PseudonymAnnounced was the ONLY §9.10-derived durable variant (grep-confirmed no other).
- Code: variant removed; counts 76→75 everywhere (lib.rs doc/tests, pruning.rs EXPECTED table, tree.rs ALL_EVENT_TYPES, wasm_conformance).
- tree.rs: **tag 59 retired as deliberate GAP, no renumbering** — every other canonical tag byte-stable → §25 KAT vectors 32/33 root `39e50b87…` byte-unchanged (Vector-32 events are AppBound/SpendApproved/TtlExtended/RecoveryEpochAdvanced/ContextTombstoned/ConsequenceTriggered/CommitBroadcastSucceeded — none is PseudonymAnnounced, none ≥tag60 shifted). KAT genuinely unchanged.
- wasm_conformance: bijection invariant correctly relaxed to injection-with-one-hole; full coverage loop asserts 0..=75 minus {59}; `!tags.contains(&59)` assertion added.
- Runtime: receive-path append DELETED (deliver_message_and_drain_buffered Recorded arm); registry insert + ContextEvent emit KEPT (ingest_pseudonym_announcement:593,601). deliver_plaintext_or_announcement Recorded arm now returns None. Strong NEW regression `received_announcement_updates_registry_without_durable_append` drives REAL direct path, asserts (a) registry updated (b) `any_append==false`. DrainRecordingEventLog refactored to `any_append` atomic (clean — can't match a removed variant).
- No forbidden issue-refs (#NNNN) on any added line across both commits.

**1 informational (non-blocking):** `.docs/specs/25-test-vectors.md:363` (Vector 32 prose) still says "closed 76-variant EventType taxonomy". KAT root/preimages genuinely unchanged so the vector is still VALID, but the descriptor count is stale (should be 75). Pure prose drift; does not affect correctness or any assertion. Recommend a one-word fix in a follow-up.

Reusable pattern: when removing one variant from a tag-keyed canonical taxonomy, RETIRE the tag as a gap (never renumber) to keep all other canonical hashes/KATs byte-stable; then relax bijection→injection-with-explicit-hole in every conformance test AND grep every spec for the stale variant-count descriptor (KATs survive, prose counts drift).
