---
name: xctx-outlet-saga-streaming-reconciliation
description: Review of xctx-outlet-saga-streaming-reconciliation.md proposal vs the two master plans (ACTOR generic-moseying-lightning + OUTLET refresh); topology-guard §3b is the one real gap
metadata:
  type: project
---

# Cross-context outlet saga↔streaming reconciliation proposal review (2026-07-09)

Reviewed `~/.claude/plans/xctx-outlet-saga-streaming-reconciliation.md` (a distilled joint-owner artifact) against ACTOR master plan `generic-moseying-lightning.md` and OUTLET refresh `outlet-report-onto-actor-REFRESH-2026-07-09.md`. Refs origin/main @ aaa574d0f, origin/feat/outlet-redesign @ 3d6313cee.

**Verdict: MOSTLY ALIGNED. The synthesis (streaming-capable saga: keep §6.2.4 envelope, drive §6.2.0.5 chunk-bridge in Commit-B, swap receipt integrity `output_hash`→`stream_manifest_hash`) is IDENTICAL to the OUTLET refresh plan's §5 Decision #1 — the outlet owner already endorses it. It does NOT break the ACTOR plan invariants I checked (Commit-cannot-fail, non-Send executor, exactly-once durable capture, Class-S, journal-holds-no-bearer-material, per-set gating).**

**THE ONE REAL GAP — §3b topology guard (b) is never applied to the cross-context STREAM.** T4 ("MLS re-encryption seam") treats per-hop re-encryption as production wiring to build, but never tests it against ADR-049 §3b guard (b) / §5.11A.6 — the exact guard that CUT broadcast hosting (PR #1898). Branch spec §6.2.0.5 (verbatim): "re-encrypting each chunk per-recipient as it crosses (source-context encryption on the outbound leg; target-context decryption on the inbound leg)"; SCP-OUT-036 story: "source encrypts for target, bridge decrypts, bridge encrypts for source's invoker"; code comment outlets.rs:6160 "This is the re-encryption + re-key step". That LOOKS like the forbidden decrypt-then-re-encrypt intermediary.

**RESOLUTION (why it is ultimately OK but must be stated):** §6.2.0(1) defines the bridge as a human who is a genuine MEMBER OF BOTH contexts, re-encrypting in their OWN local SDK ("The human's SDK is the transport"); mechanism 2 = multi-parent child whose members joined both parents. An authorized member of both sides moving data they are entitled to see is NOT the §3b-forbidden "intermediate context relaying to its own members who never joined the source." Broadcast hosting failed because the host relayed to members who never joined B; the outlet bridge has bidirectional opt-in + dual event-log. So it PASSES guard (b) — but the proposal must say so explicitly and add the §3b pass to the ADR bullet, not bury it as "T4 production seam."

**Distinction that resolves it:** §6.2.4 as-built (main) has NO cross-context re-encryption — transport leg L298 "the established interface's transport (shared-member local SDK seam, or multi-parent child bridge), NEVER a new relay primitive"; B returns an OUTPUT to an authorized caller. The re-encryption is NEW with §6.2.0.5 streaming (chunk bridge). So the topology question is genuinely raised by the streaming half and genuinely un-analyzed in the proposal.

**Invariants verified intact:**
- Commit-cannot-fail (plan L1127 / ADR L68): streaming Commit still triggers-execution + captures; no Commit-time revalidation branch added. OK.
- Non-Send executor (§6.2.4 L61 / ADR §3): streaming executor still runs supervisor-side off the mailbox; branch bridge already spawns it there. OK.
- Exactly-once durable capture (§6.2.4 L61): storing forwarded-chunk-sequence keyed by SagaId preserves "replayed Commit re-emits stored [chunks], never re-invokes". OK.
- Journal-holds-no-bearer-material (§6.2.4 L339 mark_resolved(secret_bearing=false)): durable chunk store goes in `PerContextState.xctx_committed_outputs` = Class-S SNAPSHOT (saga_prepared_state.rs:379-401), SEPARATE from the public-metadata journal. So chunk-seq store does NOT put anything in the journal. OK. (Chunks carry per-chunk operator SIGS, public, not bearer secrets → still secret_bearing=false.)
- Class-S fail-closed: chunk store is Class-S like today's output_bytes. OK.
- Per-participant-context-set gating (§3a): OUTLET refresh §2 explicitly requires try_reserve_context_set still applies. OK.

**SCP-OUT-036 ACs preserved:** wrapping bridge in saga keeps mpsc::Receiver, no-buffer, per-chunk chain_depth, both-logs-agree-on-manifest — the saga is an ENVELOPE around the unchanged bridge, not a buffering replacement. AC verified green-able.

**T1-T5 status:** T1 (durable store size), T2 (credit relay), T4 (MLS seam), T5 (SDK signature) are genuinely open joint decisions. T3 (V1-redefine vs -V2) is pre-release-trivially-decidable but fine to flag. T4 needs a §3b topology-pass added, not just "build the seam."

**Sequencing (check #4):** PR-1-rides-buffered-saga-to-compile does NOT violate a done AC on main because SCP-OUT-036 is a BRANCH story (feat/outlet-redesign), not yet on main; buffered-degenerate cross-context on main-during-PR-1 reverts nothing shipped on main. But the proposal should note the outlet branch's done-AC is only "protected" once the streaming half lands in PR-N — the window is on the integration branch, acceptable per staging.

**Recommendation: SAFE to hand to both owners WITH ONE CORRECTION** — add an explicit §3b topology-guard pass for the cross-context stream (the re-encryptor is an authorized member of both contexts / multi-parent child, therefore not the forbidden intermediate-context relay), and reclassify T4 from "production seam to wire" to "topology-validated re-encryption whose absence is the seam." Without that, a future reviewer will (correctly) flag the stream bridge as the broadcast-hosting topology that was already cut.
