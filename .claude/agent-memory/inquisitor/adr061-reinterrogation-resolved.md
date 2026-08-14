---
name: adr061-reinterrogation-resolved
description: ADR-061 revision (2026-07-13, streaming branch) — the 4 challenged premises RESOLVED; 2 new adjacent findings on §3a wait-model + spec §6.2.5 naming drift
metadata:
  type: project
---

Re-interrogation of ADR-061 revision @fa8e5eb79 (worktree scp-wt-streaming). See prior [[adr061-outlet-invocation-modes]] for the original INTERROGATE FURTHER verdict.

**All 4 originally-challenged premises RESOLVED:**
1. Timing paradox — FIXED. Seal phase now specified: Commit-transition triggers pump + does NOT sign receipt; seal-phase at stream-close finalizes manifest root from an O(log n) incremental Merkle frontier (keyed by SagaId), signs receipt, settles escrow, records both logs, reaches Committed terminal. Mid-stream crash = seal-prefix-and-close-truncated, never resume (LLM non-determinism). Receipt determinism on replay via SagaId-keyed durable root capture, not re-execution. Internally coherent.
2. Orthogonality — FIXED. Envelope now defined by GUARANTEE (exactly-once+receipt+recovery), realized cross-ctx by saga / same-ctx in-principle by journal. Bijection stated honestly as "current realization fact, not definitional identity." Same-ctx journaled transactional hypothetical does NOT conflict with §3b (journal≠saga).
3. Provenance — FIXED. ADR-049 §5 mis-cite removed + explicitly corrected (§5 IS OwnedIdentityDid, verified :122). SCP-OUT-036 findable in .docs/prds/outlet.json on branch. "found unsound doc" reference gone. All separators registered §9.18.2.
4. Fourth-mode rationale — FIXED. Re-attributed to cross-ctx atomic dual-log + signed receipt + escrow settlement; explicitly says per-chunk billing is NOT the distinguisher (present in best-effort stream too).

**2 NEW findings (adjacent, introduced by the resolution):**
- MEDIUM-HIGH: §3a reconciliation is PARTIAL. ADR-061's "Duration / ADR-049 §3a reconciliation" section reconciles only the 30s PHASE timeout (stream lives in seal phase, not phase-bounded). It does NOT reconcile §3a's OTHER clause: "FFI worker blocks-until-terminal ≤~95s, no async/poll model needed." Streaming saga reaches Committed at seal-close (potentially minutes; credit ceiling bounds chunk COUNT not wall-clock). A block-until-terminal FFI worker would block >95s, OR the streaming saga needs a return-Receiver-promptly surface that §3a says isn't needed. ADR takes on the "§3a reconciliation" burden by title but delivers half. Streaming-saga FFI is "planned"/deferred so acceptable to defer — but should note §3a wait-model needs extension for streaming, else phantom coherence.
- MEDIUM: spec §6.2.5 (written to BE ADR-061's normative summary) DRIFTS from the ADR's normative naming rule. Bullets/cells say "transactional" but table header (:358) and Naming line (:368) say "**saga**" as the envelope discriminator. "saga" is the cross-ctx MECHANISM — exactly what ADR-061 rule 32 + rejected-alt #4 forbid ("envelope defined by guarantee NOT mechanism; never name by location"). Internal contradiction in the same integration.

Verdict: PREMISES SOUND (all 4 resolved); 2 new non-blocking coherence findings named above.
