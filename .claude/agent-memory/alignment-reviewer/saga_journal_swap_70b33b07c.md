---
name: saga-journal-swap-70b33b07c
description: ADR-049 Phase 2D durable saga-journal swap + compaction + corrupt-isolation at 70b33b07c (base ef7345cd5) — ALIGNED, ship, 0 findings; mature successor to 17d651de8 with BOTH prior findings resolved
metadata:
  type: project
---

# Saga durable-journal swap + compaction @ `70b33b07c` (worktree /private/tmp/scp-journal-swap, base ef7345cd5, ADR-049 Phase 2D) — ALIGNED, ship, 0 findings

Mature successor to [[saga-journal-swap-17d651de8]] (which succeeded [[saga-journal-swap-c21d8e66e]]). 16 files +2023/-107. Same swap family + ADDS resolved-saga COMPACTION + rebased onto post-broadcast-cut main.

**What it does.** (1) Swaps prod journal Noop→durable `ProtocolRepositorySagaJournal` at all 4 prod seams (PyO3 build_saga_journal runtime.rs:1224/1226; NAPI saga_journal_from_handle:1079; UniFFI:1420; scp-node self_host.rs:643; WASM N/A). (2) COMPACTS resolved sagas (saga_journal.rs:669-740: append durable terminal marker → delete non-terminals → delete marker LAST). (3) Fault-isolates corrupt/torn/vanished entries on load (saga_journal.rs:534-603 skip-and-flag; list_keys stays hard `?`). (4) Updates ADR-049 §3b + spec §17.16.1(new compaction para)+§17.16.4(new corrupt bullet) + with_providers rustdoc + metric doc.

**BOTH `17d651de8` findings RESOLVED:** (a) MINOR metrics.rs:17 doc broadened to cover corrupt/torn/undecodable/vanished load-sweep condition (commit ccd482479). (b) OBSERVATION §17.16.4 5th-arm corrupt-entry disposition + sweep-isolation property added (commit c2ea5f5ab). The `17d651de8` STALENESS WATCH (ADR §3b "and the broadcast-hosting equivalent") RESOLVED by commit 70b33b07c — dropped after rebase onto post-cut main.

**Verified ALIGNED:**
- ARTIFACT-FLOW correct: ADR §3b pre-edit literally said swap "becomes live when bridges switch to with_providers_and_journal, a later phase" → "has landed" = completion doc, not code reshaping ADR. Spec §17.16 stays impl-state-free.
- BOTH code behaviors now spec-anchored (not code-only): compaction → §17.16.1 "Bounded-cost recovery (normative)" w/ crash-safety ordering MUST; corrupt-skip+sweep-isolation → §17.16.4 5th bullet "single unrecoverable entry MUST NOT abort recovery of remaining sagas".
- "MAY defer compaction" spec latitude vs always-compact code = CONFORMANCE not contradiction (§17.16.1 "either is conformant"; prod picks strict end, honest in spec+rustdoc).
- CRASH-SAFETY verified: marker is max-seq, deleted LAST → every intermediate crash leaves max-seq=terminal marker → load reads terminal → saga stays resolved → "never reverts to in-flight" holds. Secret-bearing zeroes evidence IN PLACE before delete → no husks.
- FORWARD OBLIGATIONS relied-not-reimplemented: mark_resolved takes SagaTerminalState={Committed,Aborted} ONLY → NeedsRepair structurally un-passable → never compacted. load_unresolved `!is_terminal()` keys on RESOLUTION (is_terminal=Committed|Aborted only; NeedsRepair.is_terminal()==FALSE @ saga_journal.rs:1314) → NeedsRepair IS re-surfaced every startup → reaches recover_needs_repair_entry @ supervisor.rs:5684. Matches spec §17.16 "keys on resolution, not FSM-terminality". {caller,target}-evidence reconstruction recovery fns UNCHANGED by diff.
- Secret-bearing FAIL-LOUD asymmetry (load skips on decode-fail / mark_resolved hard-errors `decode_entry(&bytes)?` @ :660) already spec-anchored by §17.16.2/§9.4.3 "secret bytes MUST NOT survive past next journal open" — can't honor MUST if entry undecodable → no new clause needed.
- NO stale broadcast refs in DIFF (grep empty). Remaining ADR-049 broadcast strings = 2026-06-25 WITHDRAWAL correction notices (historical record of [[bcast-hosting-saga-cut-385a35c5b]] cut), not active-feature claims.
- Enforcement only EXPANDED: pipeline_wiring 49→50; CI adds NEW `cargo nextest -p scp-testing --features sqlite` (on-disk crash-recovery round-trip), no weakening. scp-runtime compiles clean.
- Inert-but-correct scope SOUND: consumer infra runs every startup; only §6.2.4 PRODUCER (reply_saga_deferred deferred actor stub) out of scope. Empty journal = no-op replay ≠ DOA. Deferral now attributed to producer not Noop journal.

**LESSON:** When re-reviewing a matured successor branch, FIRST diff-check that the predecessor's recorded findings were resolved by name/commit (here ccd482479 broadened metric, c2ea5f5ab added §17.16.4 arm, 70b33b07c dropped stale bcast parenthetical) — converts a fresh deep-dive into a delta-verification. For compaction crash-safety: the invariant is "max-seq entry is ALWAYS terminal at every crash point" → delete-marker-LAST achieves it. CAUTION: don't transpose is_terminal assertions — re-read the matches! arm + the test asserts; NeedsRepair.is_terminal()==FALSE is what makes the resolution-predicate (not FSM-terminality) re-surface it, satisfying the spec.
