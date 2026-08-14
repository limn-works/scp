---
name: adr061-outlet-invocation-modes
description: ADR-061 outlet invocation taxonomy (delivery×envelope) interrogation — orthogonality premise false, streaming-saga timing paradox unresolved, phantom §5 citation
metadata:
  type: project
---

# ADR-061 (delivery × envelope) — interrogated @f5269dc59 (worktree scp-wt-streaming)

ADR claims outlet invocation = TWO orthogonal axes (delivery unary/streaming × envelope
best-effort/saga) → 4 modes, all supported; "cross-context is NOT a discriminator."

**Why:** verdict INTERROGATE FURTHER — one BLOCKER, two HIGH. Findings so a re-review
after ADR edits can confirm they were addressed, not re-litigate.

**How to apply:** when ADR-061 / §6.2.5 / the streaming saga (slice 3) is revised, verify:

- **BLOCKER (Q2 timing paradox unresolved).** `stream_manifest_hash` (Merkle root over
  sealed chunk seq) + signed receipt + cross-context escrow-settle are CLOSE-time artifacts;
  ADR asserts "single commit over the Merkle root inside the Commit-triggers-execution slot"
  (line 36). Root isn't known until stream ends → collides with (a) §6.2.4 Commit-time
  receipt determinism (staged state reproducible on replay — a mid-stream crash has NO
  completed output to re-emit); (b) ADR-049 §3a block-until-terminal ≤95s / 30s-phase-timeout
  (long stream inside Commit blows it; async/poll explicitly rejected in §3a); (c) §6.2.4
  crash-recovery ("re-emit stored output, never re-invoke" assumes a completed deterministic
  output). ADR rebuts the WRONG objection (per-chunk 2PC strawman) and declares victory; the
  bounded-artifact point is sound but doesn't answer WHICH phase finalizes the root. Honest
  mechanism exists (durable INCREMENTAL capture keyed by SagaId + finalize-at-close as a
  post-Commit seal/settle phase extending the §6.2.4 FSM) but ADR never specs it. NOT a
  buffering problem: incremental RFC-6962 Merkle frontier = no payload buffering, so
  SCP-OUT-036 AC[2] is NOT contradicted (don't over-correct there).

- **HIGH (Q1/Q4 orthogonality premise false-as-stated).** For outlet invocation
  envelope ⟺ location BIJECTIVELY: §3b forbids same-context sagas (saga iff 2+ distinct
  contexts); §6.2.5 DEFINES transactional ≡ "the §5.15.4/§6.2.4 saga"; ADR's own mode
  descriptions: plain=same-ctx, outlet stream=same-ctx ("same-context streaming runtime"),
  both saga modes=cross-ctx. So best-effort=same-context, saga=cross-context, no exceptions.
  "Two orthogonal axes, location not a discriminator" is contradicted by the ADR's own
  definitions. Constructive fix: define envelope by GUARANTEES (exactly-once/receipt/recovery
  by ANY mechanism — single-actor journal same-ctx, saga cross-ctx), NOT by "the saga"; then
  axes become genuinely orthogonal and a same-context transactional mode exists (consistent
  w/ §3b). Keep the naming rule; correct the premise.

- **HIGH (provenance).** Phantom citation: ADR-049 §5 is `OwnedIdentityDid`, contains NO
  "every outlet call is a stream" — that phrase exists ONLY in ADR-061 (grep-verified; ADR-049
  has zero streaming concept, only "downstream/upstream"). Smuggled premise as provenance.
  Also SCP-OUT-036 is NOT a system-of-record PRD story (grep of .docs/prds/*.json = absent;
  only code-comment ACs in registry.rs) and the "option found unsound" doc it cites doesn't
  exist. §9 Class-S citation IS valid; §6.2.4 "unary transactional" tag DID land (line 242).

- **MEDIUM (Q3 rationale mis-attribution).** "streaming saga is the ONLY mode that bills
  exactly-once across a mid-stream crash" is imprecise: per-chunk exactly-once billing comes
  from monotonic Class-S credit (`commit_class_s_keep`), present ALSO in best-effort outlet
  stream. Saga uniquely adds cross-ctx atomic dual-log + signed receipt + caller-side escrow
  settle — NOT the billing property. Fourth mode is real; sole stated justification misattributes.

- **LOW.** No phantom mode among the four (each reachable+useful); scope NOT inflated on
  cardinality. Risk is the fourth mode declared SOUND before its mechanism is specced (DOA risk).

Links: [[adr049-classm-floor-registry]] (§3b saga-admission), [[worktree-grep-path-trap]].
