# ADR-061: Outlet Invocation Modes — Delivery × Envelope Taxonomy

**Status:** Accepted (2026-07-12)

**Context sources:** spec §5.4 (outlet registration/invocation), §6.2 (cross-context outlet interfaces), §6.2.4 (cross-context outlet invocation saga), §7.3.8 (invocation caveats); PRD SCP-OUT-036 (streaming bridge, AC[2] "bridge does not buffer"); ADR-049 §5 ("every outlet call is a stream" ergonomics), §9 (Class-S crash-safety). Supersedes the informal "streaming bridge vs. saga" framing (previously carried only in planning notes and a doc retained as "an option found unsound"), which was never written into a canonical artifact — the absence of this ADR is why the delineation was repeatedly re-litigated.

## Decision

An outlet invocation is classified along **two orthogonal axes**, not by where it runs. "Cross-context" is **not** a discriminator (it correlates with, but is not identical to, the envelope axis).

- **Delivery** — how the result is returned:
  - **unary** — a single response. Committed integrity artifact: `output_hash`.
  - **streaming** — a sequence of operator-signed chunks (`SCP-OUTLET-CHUNK-SIG-V1`) with per-chunk credit/escrow. Committed integrity artifact: `stream_manifest_hash` (RFC-6962 Merkle root over the sealed chunk sequence), which is bounded even for an unbounded stream.
- **Envelope** — the transactional guarantees around the call:
  - **best-effort** — a bare invocation: no exactly-once, no receipt, no crash recovery.
  - **transactional (saga)** — the §5.15.4 / §6.2.4 saga: exactly-once execution, durable `SagaId`-keyed output capture, a signed receipt, dual event-log recording, and crash recovery.

The cross product yields **four canonical modes**, all supported:

| | **best-effort** (no saga envelope) | **transactional** (saga: exactly-once, receipt, recovery) |
|---|---|---|
| **unary** (→ `output_hash`) | **plain outlet invocation** | **outlet invocation saga** (§6.2.4) |
| **streaming** (→ `stream_manifest_hash`) | **outlet stream** | **streaming saga** |

- **plain outlet invocation** — unary, best-effort. The base same-context call (`invoke_outlet`). On `main` today.
- **outlet invocation saga** — unary, transactional. The existing §6.2.4 cross-context saga; commits `output_hash`. On `main` today.
- **outlet stream** — streaming, best-effort. Signed chunk stream with credit; no transaction envelope. The same-context streaming runtime.
- **streaming saga** — streaming, transactional. The **synthesis**: the §6.2.4 saga envelope whose committed integrity artifact is `stream_manifest_hash` instead of `output_hash`, and whose Commit-triggers-execution slot drives the chunk stream. Gains streaming for the transactional path; gains atomicity/recovery/receipt for the streaming path. This is the only mode that is both streamed **and** exactly-once — required for a **paid, metered LLM outlet** that must stream tokens while billing exactly-once across a mid-stream crash.

**Naming rule (normative for all downstream artifacts).** Discriminate outlet invocation by **delivery (unary/streaming)** and **envelope (best-effort/saga)**. Do **not** use "cross-context" as the discriminating qualifier for these modes — it names *where* the call runs (an orthogonal deployment property), not *what kind* of call it is. "unary" and "streaming" are used as the industry-standard matched pair (cf. gRPC); "unary" names the response *cardinality* (one), not an implementation ("buffered").

## Rationale

- **Why streaming at all.** The dominant outlet is an LLM. A unary-only model breaks it: no token-by-token delivery (time-to-first-token), a hard output cap, and no incremental metering. SCP-OUT-036 AC[2] ("bridge does not buffer") mandates non-buffering delivery for the streaming path — an artifact-flow constraint, not an implementation choice.
- **Why keep the unary saga.** Atomic one-shot calls that need a receipt and crash recovery (and do not need streaming) are fully served by the existing §6.2.4 saga. Retiring it would lose exactly-once/receipt/recovery for the transactional case.
- **Why the synthesis (streaming saga) is sound, and the earlier "streaming saga" was not.** The rejected framing forced *streaming into 2PC* — a two-phase commit **per chunk** — which is unsound (an unbounded stream cannot be a single atomic prepare/commit, and per-chunk 2PC destroys the streaming property). The correct synthesis does **not** 2PC each chunk: the saga's *committed artifact* changes from a single `output_hash` to a **bounded** `stream_manifest_hash` (a Merkle root that summarizes an arbitrarily long chunk sequence in fixed size), and the saga Commit still commits **once**. Streaming lives inside the Commit-triggers-execution slot; the transaction commits the manifest root. Bounded artifact + single commit = both properties without per-chunk 2PC.
- **Class-S discipline.** Streaming credit/escrow counters are Class-S (ADR-049 §9): consumed via `commit_class_s_keep` (monotonic, never rolled back on a coalesce-window crash), identical to the §7.3.8 caveat counters (ADR-061 shares this discipline with the value-caveat enforcement work).

## Alternatives considered and rejected

1. **Unary saga only (no streaming).** Rejected: breaks LLM outlets and violates SCP-OUT-036 AC[2].
2. **Streaming bridge only; retire the §6.2.4 saga.** Rejected: loses exactly-once/receipt/crash-recovery for transactional calls; a paid one-shot call would have no atomicity.
3. **A "streaming saga" that 2PCs each chunk.** Rejected as unsound (see Rationale) — this is the framing the retained "found unsound" note refers to. The accepted synthesis is distinct: single commit, Merkle-manifest artifact.
4. **Keep "cross-context" as the mode discriminator.** Rejected: it is a deployment location, not a call kind; using it as the discriminator is precisely what caused the recurring confusion.

## Consequences

- Spec §6.2 gains a canonical "Outlet Invocation Modes" pointer to this ADR; §6.2.4 is tagged as the **unary, transactional** corner. The **delivery** axis (unary/streaming) is a §5.4 concept (applies even same-context); the **envelope** axis is §6.2.4.
- The committed integrity artifact is `output_hash` for unary and `stream_manifest_hash` for streaming; a receipt (`SCP-XCTX-RECEIPT-V1`) over a streaming saga carries `stream_manifest_hash`.
- Implementation status at acceptance: *plain outlet invocation* and *outlet invocation saga* are on `main`; *outlet stream* is in progress (same-context streaming runtime); *streaming saga* is planned (cross-context streaming slice). This ADR defines the target taxonomy; downstream sections note per-mode status.
