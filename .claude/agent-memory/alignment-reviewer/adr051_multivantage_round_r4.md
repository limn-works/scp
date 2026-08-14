---
name: adr051-multivantage-round-r4
description: ADR-051 causal-DAG round-4 (multi-vantage clock reframe + small-context floor removal) review — APPROVE, clean
metadata:
  type: project
---

# ADR-051 Multi-Vantage Clock Reframe Review (2026-06-19) — APPROVE

Round following [[adr051_causal_dag_review]] (which was CHANGES-NEEDED on the unqualified `paymentHistory` claim at 19:593). This round: convergent clock reframed from "median-of-member-receive-times"/"member-median" → **multi-vantage median (sender/node/relay/receiver-quorum, anchored on receiver quorum, clamped to max(sender,relay-ingest) lower bound)**; the "small-context floor → local-only" fallback fully REMOVED (construction is size-independent: receiver-stamp spread is latency/online-status, not member count).

UNCOMMITTED diff: ADR-051 (new) + phase-2.md (ADR-011 amendment) + specs 07/09/19/25.

**APPROVE — clean.** All four verification axes pass:
1. Multi-vantage propagation complete: every clock mention in 07:714 (tool-rate now "count×multi-vantage-clock"), 09:813 (checkpoint DAG-leaf note), 19:483/593, phase-2 §6 amendment names the 4 vantages / anchors on receiver quorum. No stale "member-median"/"median-of-member-receive-times" survives outside explicit REJECTED negations (ADR-051:19/21/96, phase-2:943).
2. Small-context floor fully removed — only explicit "no small-context floor" negations remain (ADR-051:96, :108).
3. Round-3 fixes all coherent: §9.8.5 sequence no longer in app-message Merkle leaf (old `SHA-256(sequence||event_type||...)` formula GONE from all specs; new `SHA-256(0x00 ‖ rmp_serde(Event))` consistent across 07:125, 09, 25:363); §6 cross-context `ToolInvoked`/`CrossContextToolInvoked` carved out of per-author exclusion (commit-ordered, `tool_invoked_event_id` is a signed `CrossContextToolReceipt` field per spec 06:299/283 — verified grounded); §7.3.7 tool-rate line qualified; **19:593 `paymentHistory` NOW qualified (prior round's residual finding CLOSED)**; frontierRoot-in-signed-preimage (SCP-CHECKPOINT-V2) present ADR-051:58/106.
4. One coherent story; cross-refs resolve (note: phase-2's "cross-context tool-call saga (§6)" = SPEC file 06, NOT ADR-051's own §6 median-clock — context-disambiguated, accurate); NO `#NNNN` issue-refs added; taxonomy=75 (25:363 says 75-variant; EventType enum in phase-2 has exactly 75 variants; PseudonymAnnounced removed from enum, only in exclusion-list comments); no contradiction introduced.

Reusable: when a clock/median construction is reframed, the propagation surface is every spec that names the OLD construction OR claims to depend on "the convergent clock" — grep both the old phrase AND generic "convergent clock"/"median clock" and confirm each either (a) names the new multi-vantage shape, or (b) explicitly states it does NOT need the clock (e.g. tool_invocation_count needs the count not the clock).
