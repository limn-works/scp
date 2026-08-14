---
name: adr051-causal-dag-clock
description: ADR-051 causal-DAG application-event ordering + convergent receiver-quorum median clock — crypto review (APPROVE) of the node-vantage-cut / max()-clamp-removed simplification
metadata:
  type: project
---

ADR-051 (.docs/adrs/ADR-051-causal-dag-application-event-ordering.md), Accepted 2026-06-19, Phase 6. Model decided; implementation is a separate forward program sequenced AFTER ADR-011 event-log unification. Review verdict: **APPROVE** (4 non-blocking findings, all implementation-program obligations).

**What it does:** application events (MessageSent/ToolInvoked/PaymentReceived) are excluded from the canonical RFC 6962 Merkle log in the interim (local ContextEvents, anchored=false), and in the end state re-enter via a causal DAG (must-resolve + must-include-frontier validated head refs, deterministic linearization by ascending leaf hash). Convergent time = receiver-quorum median.

**The simplification reviewed (vs an earlier rev):**
- Cut the "node" vantage → 3 vantages: sender, relay, receiver-quorum.
- Replaced `max(median, sender, relay)` clamp with floor-only: receiver-quorum median IS the canonical value; sender/relay are *early-direction consistency lower-bound assertions* only. median MUST be ≥ max(sender, relay-ingest) else flagged inconsistent → NO durable consequence (local-throttle fallback). Floors MUST NOT raise the value above the receiver median.

**Crypto assessment:**
- CONVERGENT + SOUND: median over a deterministically-CLOSED quorum (§5 anchoring-epoch-members predicate over the convergent commit-ordered log → observation-order-independent), even-quorum tie = LOWER of two central samples (integer ms, never mean). Unclosable cut → no durable value (no nondeterministic fallback). Every honest member computes identical median.
- UPWARD-LEVER REMOVED (C02 closed): old max()-clamp let colluding sender+relay stamp LATE to push canonical time past receiver-witnessed → dodge rate window. New floor-only: a high floor only trips the inconsistency check → DENIES the durable consequence (self-DoS), never shifts time. Genuinely gone.
- RESIDUAL (acknowledged, by construction): the floor bounds only the EARLY direction. A receiver-Sybil-LATE-majority can still inflate the median later-in-time (the rate-dodge direction). ADR owns this as the soft-signal residual (lines 77/113). Not Byzantine-robust; sound only because the zero-trust local throttle (§7) is the live defense and NEVER consumes this clock.
- HONEST CHARACTERIZATION CORRECT (no overclaiming): value rests on honest-majority-of-receivers (SOFT signal, explicitly not a cryptographic guarantee); sender/relay floors are NOT Byzantine-robustness for the value; C05 relay delay-not-forge veto + C03 no-size-floor/confidence-annotation honestly scoped.
- C01 anti-replay: field set {context_id, epoch, leaf_hash, receiver_did, receive_time_ms} is SEMANTICALLY SUFFICIENT — can't lift an attestation across event/context/receiver/epoch.

**Findings (all non-blocking, implementation-program obligations):**
- F1 MEDIUM: C01 receive-attestation preimage specifies the FIELD SET but NOT byte construction (no domain separator, no BE32(len) prefixes on var-length context_id/receiver_did). SAME CLASS as the 2026-03-05 audit CRITICAL CRYPTO-01/02 (InnerEnvelope/BroadcastEnvelope naive concat). NEW signed struct + sole clock value-source → MUST use §9.5.1 pattern ("SCP-RECEIVE-ATTEST-V1:" + BE32(len)-prefixed fields), mirror SCP-CHECKPOINT-V1 at 23-sync-and-offline-strategy.md:332. Fold into ADR §6 Security Req (line 113) now.
- F2 MEDIUM: §23.16.1 wire-format at 23-sync-and-offline-strategy.md:332 STILL says SCP-CHECKPOINT-V1 with no frontierRoot/receive-time. 09-security-model.md:813 got only a prose DAG-leaf note. ADR §5/§111 mandate versioned SCP-CHECKPOINT-V2 w/ frontierRoot INSIDE signed preimage. Authoritative byte spec not yet updated — owed by impl program (acceptable: ADR is model-only).
- F3 LOW: §25 diff only 76→75 (PseudonymAnnounced retirement reconcile). The §114 KAT battery (DAG linearization w/ partial-obs snapshot; even-quorum/tied-central/lower-of-two median; consistency-floor used-vs-flagged; relay-inflated-ingest proving floor can't raise; multi-relay median; frontierRoot unsorted/dedup bytes; consequence-leaf) all owed by impl program. ADR correctly says happy-path triple insufficient.
- F4 LOW: ADR line 66 "deterministic median-of-relays" must reference the §75 lower-of-two even tie rule explicitly, else implementers could pick a different relay-axis tie convention → non-convergent FLAGGING (one honest member flags inconsistent, another doesn't).

**Nothing internal to the ADR broke in the simplification.** frontierRoot/SCP-CHECKPOINT-V2/even-quorum-lower-of-two all survived. Rejected node-vantage + max()-clamp correctly recorded w/ rationale (alternatives line 101).
