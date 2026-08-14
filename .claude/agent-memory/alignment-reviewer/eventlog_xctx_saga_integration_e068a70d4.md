---
name: eventlog-xctx-saga-integration-e068a70d4
description: Phase-2 event-log taxonomy 75→77 — CrossContextToolInvoked/DivergenceMarker variants + #1849 saga-append migration; ALIGNED w/ 1 doc-precision note
metadata:
  type: project
---

# Event-Log #1849 Cross-Context Saga Integration @ `e068a70d4` (2026-06-20) — ALIGNED (1 doc-precision note)

Commit `e068a70d4` integrates concurrently-merged cross-context tool saga (#1849) with Phase-2 closed EventType taxonomy. 10 files +417/-136. Extends frozen 75-variant taxonomy → 77: adds `CrossContextToolInvoked` (tag 76) + `CrossContextDivergenceMarker` (tag 77); migrates 3 string-named saga appends (`format!("ToolInvoked:{id}")`, `"CrossContextToolInvoked:{id}"`, `"CrossContextDivergenceMarker:{id}"`) to typed convergent leaves carrying committer-assigned timestamps.

**Why ALIGNED:**
- `CrossContextToolInvoked`: EXPLICITLY named in ADR-011 Amendment §6 carve-out (phase-2.md:944). Spec-sanctioned, not invented.
- `CrossContextDivergenceMarker`: NOT named in phase-2.md §6 carve-out (:943-948 names only ToolInvoked/CrossContextToolInvoked) BUT fully normatively specified in spec §6.2.4 (06-cross-context-communication.md:319 "Dual event-log recording" — `NeedsRepair ⇒ both sides MUST emit a signed CrossContextDivergenceMarker`, :321 signature preimage, :333 committed_side tag mapping) + separator-registry row (09-security-model.md:1629 `SCP-XCTX-DIVERGENCE-V1`). So it traces to a real spec — NOT phantom provenance. Adding it to the taxonomy is artifact-flow-clean.
- Convergent timestamps: both new leaves + ToolInvoked draw committer-assigned timestamp from B's signed `recorded_timestamp_ms/1000` (the receipt's `timestamp_ms`), the SAME staged convergent instant a replayed Commit reproduces byte-for-byte (§7.3.1/§9.9.3/§6.2.4 Recorded-timestamp). NOT actor-local clock reads. `cross_context_invoked_leaf` re-reads it from forwarded receipt bytes; supervisor threads `committed_timestamp_secs` through DivergenceMarkerPlan + SagaPhaseMessage. Consistent w/ Phase-2 convergent model.
- Closed-taxonomy discipline RESPECTED: tags 76/77 = next free after max 75; retired tag-59 gap (PseudonymAnnounced) PRESERVED; all 5 pinned tests bumped coherently (lib.rs roundtrip + 77-count, tree.rs ALL_EVENT_TYPES + distinct-tags + 36..=77 occupancy, pruning.rs EXPECTED[77] classification, wasm_conformance 0..=77-minus-59 bijection); structural pinning intact. is_structural_event: DivergenceMarker=structural (accountability class, ADR-030 §2c, same as Consequence*), ToolInvoked-analog CrossContextToolInvoked=operational. KAT §25 V32 updated (75→77).
- Right layer: taxonomy lives in scp-event-log; #1849 saga code consumes it. The variant addition belongs HERE, not in #1849. Migration from string-names to typed is the integration point. Correct.
- No scope-creep: exactly 2 variants + 3 append migrations + the convergent-timestamp plumbing they require. lifecycle_helpers.rs MessageSent-no-longer-durable test rename + messaging_helpers 75→77 comment are consequential touch-ups, not new scope. No `#NNNN` in new SOURCE (only error codes SCP-SAGA-13037..13040, which are error-code strings not issue refs); §/ADR refs throughout.

**1 doc-precision note (non-blocking, NOT a provenance hole):** lib.rs:101-102 comment says "the ADR-011 Amendment §6 cross-context-saga carve-out added the 2 `CrossContext*` variants" — slightly over-attributes: the phase-2.md §6 carve-out text names only `CrossContextToolInvoked`. `CrossContextDivergenceMarker`'s sanction lives in spec §6.2.4 (06-cross-context), not the ADR amendment prose. The 25-test-vectors.md edit has the same phrasing. Optional tightening: cite §6.2.4 alongside the §6 carve-out for the marker. Provenance is sound either way (both refs are correct & present); only the attribution sentence conflates two upstream sources into one.

Verdict ALIGNED. Taxonomy extension is spec-grounded and artifact-flow-clean. CrossContextDivergenceMarker does NOT lack spec sanction (§6.2.4 is normative). No spec amendment strictly required; the only improvement is a one-line doc-comment citation fix.
