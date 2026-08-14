---
name: adr051-multivantage-clock
description: Black-hat findings on ADR-051 causal-DAG + multi-vantage median convergent clock (receiver-quorum anchored)
metadata:
  type: project
---

# ADR-051 Multi-Vantage Median Clock — Attack Surface

File: `.docs/adrs/ADR-051-causal-dag-application-event-ordering.md`
Substrate: phase-2.md ADR-011 amendment (convergence taxonomy); consumers §7.3.7 suspension, §7.3.2 tool_count, §19.7 velocity.

Canonical event time = median(receiver-attestations) CLAMPED ≥ max(sender, relay-ingest), over deterministically-closed receiver quorum (anchoring-epoch membership who attested by bounded deadline). No small-context floor. Framed as SOFT signal, backstopped by zero-trust local throttle (§7, §23.16.4).

## Key findings

### BLACK-C01 (HIGH, design-sound-but-underspecified): receive-attestation not bound to event hash in ADR text
ADR §6 says receivers "sign a receive-attestation" but never specifies the signed preimage MUST bind the canonical leaf hash + context + epoch. Without explicit binding => attestation replay across events / pre-signing. Security-req #4 lists "signed by role's key" but not "binds {leaf_hash, context_id, epoch, receiver_did}". Must be normative.

### BLACK-C02 (HIGH): clamp floor is the real lever, not the median. sender+relay collude to RAISE floor
Canonical time clamped ≥ max(sender, relay-ingest). A colluding sender+relay both stamp LATE (future). Clamp forces canonical time to that late value REGARDLESS of honest receiver median. "Lower bound only" is false for the OUTPUT: raising the lower bound above the median raises the output. Lets a sender compress its own events into a narrow late window (dodge rate) OR push an event past a window boundary. Receiver median provides NO downward correction because clamp is max(). Node "upper-sanity" cross-check is the only guard and node incentive is unspecified.

### BLACK-C03 (MEDIUM): "no floor" + few receivers => 1 honest receiver median is that receiver's clock
Size-independence claim (spread = latency not count) true for HONEST spread, but with 2-3 receivers the quorum median = a single receiver value; one Sybil receiver = majority. Admission cost is the ONLY bound and §9.3 explicitly says admission is a DETERRENT NOT A GUARANTEE. Small high-value contexts (escrow/payment 2-4 members) are exactly where suspension consequence matters AND where receiver quorum is smallest.

### BLACK-C04 (MEDIUM): node vantage incentive unspecified; sender self-hosting node not excluded by protocol
ADR asserts "senders are not assumed to self-host nodes" but nothing PREVENTS it. If sender hosts node, node stamp colludes => 2 of 3 lower-bound/upper-sanity vantages captured by one party. Node is "infrastructure" with no defined opposing incentive (unlike receiver=counterparty, sender=under-reporter).

### BLACK-C05 (MEDIUM): closure liveness window is a relay-tunable knob
Cut closes iff every anchoring-epoch member has checkpoint covering F within bounded liveness window. Relay selectively delays ONE honest member's checkpoint past the window => cut never closes => "no durable consequence (local fallback)". Relay can SUPPRESS every durable suspension at will by delaying one checkpoint. Local throttle still fires but the durable shared record (the whole point) never forms. This is relay veto over the consequence, restated.

### BLACK-C06 (LOW/spec-gap): membership churn during anchoring epoch
Closure = "anchoring-epoch membership". Attacker times a Join right before the cut so a fresh Sybil is in the membership set and must attest; or a Leave to drop an honest attester. The "anchoring epoch" pin needs to be the epoch the EVENT was committed in, not the cut-evaluation epoch, or churn shifts the closure set.

### Resists attack (genuine strengths)
- Count axis: must-include-frontier + per-author-aggregate rule => leaf-hash tie-break grind changes no count. Sound.
- Sender-only backdating-EARLY: clamp ≥ sender's own stamp blocks a sender claiming early to spread. Sound (that direction).
- §9.9.3 equal-frontier/equal-root: frontierRoot in signed preimage closes relay forging the frontier field. Sound.
- Local throttle independence: biasing clock degrades only durable record, live spam defense intact. Genuinely good layering.
