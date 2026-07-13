# ADR-061: Outlet Invocation Modes — Delivery × Envelope Taxonomy

**Status:** Accepted (2026-07-12). Revised 2026-07-13 after a four-lens review (architecture, premises, cryptography, spec-alignment) — the revision corrects a fabricated citation, defines the envelope axis by guarantee rather than by mechanism, and specifies the streaming-saga seal phase + receipt separator that the first draft left implicit.

**Context sources:** spec §5.4 (outlet registration/invocation) and §5.4.5 (Progressive Output / streaming delivery); §6.2 (cross-context outlet interfaces) and §6.2.4 (cross-context outlet invocation saga — its Prepare/Commit FSM, exactly-once durable `SagaId`-keyed capture, dual event-log, receipt, §17.16.4 crash recovery); §7.3.8 (invocation caveats, Class-S caveat counters); §9.18.2 (domain-separator registry); ADR-049 §3 (Commit *triggers* execution — the generic executor cannot cross the actor mailbox), §3a (bounded block-until-terminal saga wait; 30 s per-phase timeout), §3b (a saga is justified ONLY by a harmful partial commit across 2+ distinct contexts), §9 (Class-S crash-safety, `commit_class_s_keep`); PRD SCP-OUT-036 (streaming outlet delivery; AC "bridge does not buffer"). **Anchor-integration note:** §5.4.5 and SCP-OUT-036 originate on `feat/outlet-redesign` and MUST be integrated onto the implementing branch before the streaming-saga slice (see Consequences) — an ADR must not cite artifacts an agent cannot find on the branch.

**Supersedes:** the informal "every outlet call is a stream" unification (a *planning-note* framing, never an ADR). ADR-061 deliberately makes **unary and streaming genuinely distinct modes** with *different* committed integrity artifacts (`output_hash` vs `stream_manifest_hash`); a unary call is NOT modeled as a 1-chunk stream. (An earlier draft mis-cited this framing as "ADR-049 §5"; ADR-049 §5 is `OwnedIdentityDid` and contains no streaming concept. The mis-citation is removed.)

## Decision

Classify an outlet invocation by **two axes**, never by *where* it runs:

- **Delivery** — the shape of the response (a §5.4/§5.4.5 property; applies even same-context):
  - **unary** — a single response; committed integrity artifact `output_hash`.
  - **streaming** — a sequence of operator-signed chunks (`SCP-OUTLET-CHUNK-SIG-V1`) with per-chunk credit/escrow; committed integrity artifact `stream_manifest_hash` (RFC-6962 Merkle root over the sealed chunk sequence; a fixed 32 bytes regardless of stream length).
- **Envelope** — defined by its **guarantee**, NOT by a mechanism: **best-effort** (no exactly-once, receipt, or crash recovery) vs **transactional** (exactly-once execution, a signed receipt, durable `SagaId`-keyed capture, dual event-log recording, crash recovery). The transactional guarantee is *realized* by a mechanism chosen by locality: **cross-context by the §6.2.4 saga** (the only justification for a saga per ADR-049 §3b), and — in principle — same-context by a single-actor journal. Defining the axis by the guarantee (not "the saga") is what keeps it orthogonal to delivery and to location.

**On the envelope↔location correlation (a review finding, stated honestly).** For the modes SCP builds *today*, the transactional guarantee is realized only by the cross-context saga (§3b forbids a same-context saga), so best-effort⟺same-context and transactional⟺cross-context are presently a bijection. This ADR still names modes by **delivery + guarantee, never by location**, because (a) the guarantee, not the deployment, is the property a caller reasons about; (b) it is forward-compatible with a future same-context journaled transactional mode; and (c) naming by location is precisely what caused the recurring confusion. The bijection is a *current realization fact*, not a definitional identity.

The cross product yields **four canonical modes**, all supported:

| | **best-effort** | **transactional** (exactly-once + receipt + recovery) |
|---|---|---|
| **unary** (→ `output_hash`) | **plain outlet invocation** — the base same-context call | **outlet invocation saga** (§6.2.4; realized cross-context) |
| **streaming** (→ `stream_manifest_hash`) | **outlet stream** | **streaming saga** (realized cross-context) |

- **plain outlet invocation** — unary, best-effort: base `invoke_outlet`. On `main`.
- **outlet invocation saga** — unary, transactional: §6.2.4; commits `output_hash`. On `main`.
- **outlet stream** — streaming, best-effort: signed chunk stream + Class-S credit, no transaction envelope. (Same-context streaming runtime.)
- **streaming saga** — streaming, transactional: the §6.2.4 envelope extended with a **seal phase** (below), committing `stream_manifest_hash`.

**Naming rule (normative).** Discriminate by delivery (**unary**/**streaming**) and envelope guarantee (**best-effort**/**transactional**). Never use "cross-context" as a mode discriminator. "unary"/"streaming" are the industry matched pair (cf. gRPC); "unary" names response cardinality, not an implementation ("buffered").

## Streaming-saga mechanism (the seal phase)

The first draft's "the saga commits once over the Merkle root" was imprecise: the root is a *close-time* artifact (it does not exist until the stream ends), so it cannot be committed at the Commit *transition*. The §6.2.4 FSM is extended with a distinct **seal/finalize phase**:

1. **Commit-transition** (unchanged shape, prompt): confirms the reservation and *triggers* the pump (ADR-049 §3 — Commit triggers execution; the executor cannot cross the mailbox). It does **not** block for the stream and does **not** yet sign a receipt.
2. **Streaming** (off-mailbox pump): chunks are (a) forwarded to the caller as produced (`mpsc::Receiver`, no buffering — SCP-OUT-036 AC preserved) and (b) captured durably and *incrementally*, keyed by `SagaId`: an **O(log n) RFC-6962 Merkle frontier** plus the per-chunk credit ledger, persisted as chunks arrive. This durable capture is a **replay snapshot, not a bridge buffer** — it never gates caller-forward latency and never accumulates the full payload set in memory (the batch `compute_chunk_manifest_root(&[…])` is a convenience for bounded inputs; the pump MUST use the incremental frontier).
3. **Seal-phase / stream-close**: finalize the manifest root from the frontier, sign the streaming receipt, settle escrow (`settle_at_close` → refund = reserved − billed), record both event logs (`OutletInvoked` target-side, `CrossContextOutletInvoked` caller-side), then FSM → `Committed`. The atomic `Committed` terminal is reached **at close**, not at the Commit-transition.

**Duration / ADR-049 §3a reconciliation.** A long stream must not sit inside the Commit-B phase and blow the 30 s phase timeout. The stream executes in the **seal phase**, whose duration is bounded by the invoker-controlled credit/escrow envelope (each billable chunk consumes signed credit; the cumulative ceiling `effective_max_billable_chunks` caps total emission), **not** by the saga phase timeout. The Commit-transition itself completes promptly.

**Mid-stream crash: seal-prefix-and-close, never resume (normative).** Re-invoking a non-deterministic or side-effecting outlet (an LLM produces different tokens) would break §6.2.4's "replayed Commit re-emits the stored output, never re-invokes." On crash mid-stream the recovery MUST **seal the durable chunk prefix and close the stream truncated**: compute the manifest root over the sealed prefix, sign the receipt over that truncated manifest, settle escrow at the prefix's `billed_count`. A replayed Commit re-emits the sealed prefix + terminal close and does **not** resume the outlet. The `CancelAckTracker` billing-ceiling (`accrue only at-or-below cancel-ack-seq`) is exactly the primitive that makes a truncated close well-defined.

## Receipt (streaming): a distinct separator, a different reproducibility mechanism

The §6.2.4 `SCP-XCTX-RECEIPT-V1:` preimage is closed with `Fixed32(output_hash)` and a self-verifiability obligation that carries the **JCS output bytes inline** so a verifier recomputes `SHA-256(output)`. A manifest root cannot occupy that slot under the same separator (a verifier cannot tell whether to recompute `SHA-256(bytes)` or a Merkle root — an ambiguous, non-domain-separated receipt). Therefore:

- **New separator `SCP-XCTX-STREAM-RECEIPT-V1:`** for streaming-saga receipts (registered in §9.18.2 alongside `SCP-OUTLET-CHUNK-SIG-V1` and the `SCP-OUTLET-CHUNK-V1` manifest-leaf domain). The unary `SCP-XCTX-RECEIPT-V1` stays exactly as specified.
- **Different reproducibility mechanism (normative).** The streaming receipt carries the **32-byte manifest root directly** (it cannot carry the chunk sequence without defeating boundedness). Its reproducibility on replay comes from the **`SagaId`-keyed durable capture of the root at stream-close**, never from re-executing the stream — replacing the unary "output canonicalization obligation" (carry-bytes-and-recompute) with a "durable root capture at close" obligation. A third-party auditor holding only the receipt gets **root-binding** verification (the root commits the ordered, counted, per-chunk-signed sequence), not inline-output recomputation.

## Rationale

- **Why streaming.** The dominant outlet is an LLM; unary-only breaks token-by-token delivery, caps output, and prevents incremental metering. SCP-OUT-036 mandates non-buffering delivery.
- **Why keep the unary saga.** Atomic one-shot calls needing a receipt + recovery (not streaming) are fully served by §6.2.4.
- **Why the synthesis is sound (and per-chunk 2PC is not).** Per-chunk 2PC is unsound (an unbounded stream is not a single atomic prepare/commit, and it destroys streaming). The synthesis instead commits a **bounded** `stream_manifest_hash` **once, at the seal phase** — the Merkle root summarizes an arbitrarily long sequence in 32 bytes, so a single seal-commit suffices. Boundedness is the enabling lemma; the seal phase is the mechanism.
- **Class-S composition is clean (affirmative).** The saga Prepare reservation is *reversible* (RAII drop-on-not-commit, pre-Commit); the per-chunk stream credit is *Class-S monotonic* (`commit_class_s_keep`, post-Commit, never un-consumed on a coalesce crash). They never collide: aborts occur pre-Commit (pre-stream); `settle_at_close` refunds only the *unused reservation ceiling* (reserved − billed), never a rollback of already-spent credit. On `NeedsRepair`, §6.2.4 already declines to auto-void the economic reservation (settled by the signed divergence marker + operator repair).
- **No-buffering + exactly-once is not a contradiction (affirmative).** Forward-as-produced to the caller and durable-incremental-seal are two sinks (write-through), not buffering; the durable sink is an O(log n) frontier, not the payload set.
- **What the transactional envelope uniquely adds (fourth-mode rationale, corrected).** Per-chunk exactly-once *billing* comes from the Class-S credit ledger — present in **best-effort outlet stream too**, so it is NOT what distinguishes the streaming saga. The saga uniquely adds **cross-context atomic dual-log recording, a signed receipt, and caller-side escrow settlement**. The streaming saga is the intersection of two first-class features (cross-context transactionality × streaming delivery) — the required mode for a paid, cross-context, metered LLM outlet.
- **Equivocation resistance (affirmative gain over the unary saga).** Because each Merkle leaf hashes `jcs(chunk)` including the operator's per-chunk signature and sequence, the manifest root binds the ordered, counted, individually-signed sequence — an operator cannot stream one content to member X and another to Y and commit a root covering only one.

## Alternatives considered and rejected

1. **Unary saga only (no streaming).** Breaks LLM outlets; violates SCP-OUT-036.
2. **Streaming bridge only; retire the §6.2.4 saga.** Loses exactly-once/receipt/recovery for transactional calls.
3. **A "streaming saga" that 2PCs each chunk.** Unsound (see Rationale). The accepted synthesis is single-seal-commit over a bounded Merkle root.
4. **Keep "cross-context" as the mode discriminator.** It is a deployment location, not a call kind — the source of the recurring confusion.
5. **Reuse `SCP-XCTX-RECEIPT-V1` for the streaming receipt.** Rejected: ambiguous verification algorithm in a closed preimage; requires the distinct `SCP-XCTX-STREAM-RECEIPT-V1` separator.

## Consequences

- **§6.2.4 gains a seal-phase** FSM extension for the streaming saga; §6.2.5 carries the normative mode summary; §6.2.4 is tagged as the unary/transactional corner.
- **§9.18.2 registry rows** must be added: `SCP-OUTLET-CHUNK-SIG-V1`, the `SCP-OUTLET-CHUNK-V1` manifest-leaf/interior domain, and `SCP-XCTX-STREAM-RECEIPT-V1`.
- **Upstream anchors must be integrated onto the implementing branch**: spec §5.4.5 (Progressive Output / streaming delivery) and PRD SCP-OUT-036, currently on `feat/outlet-redesign`. The streaming-saga slice must not proceed until they are present (artifact-flow invariant).
- **Wiring obligations** (streaming slices): compute `stream_manifest_hash` and `chunks_billed` from **one** retained canonical chunk sequence; invoke `verify_chunks_billed` → `EventLogError::ChunksBilledMismatch` at event-log append; reconcile `StreamEscrow` settled `billed_count` against the manifest-derived count. Production sites currently hardcode `stream_manifest_hash: [0u8;32]` (e.g. `outlets/invoke.rs`, the uniffi bridge, the MCP surface) — these are the wiring targets.
- **Defense-in-depth (streaming slice):** replace the free-form `StreamSignerError::Custody { detail: String }` with a bounded category enum so a custody adapter cannot leak key material / preimage into structured logs.
- **Chunk-sig replay resistance** rests on `request_id` (UUIDv7) uniqueness + `caveats_binding` pinning (`stream_epoch` is not in the chunk preimage) — to be noted in §5.4.5.
- Implementation status: *plain outlet invocation* and *outlet invocation saga* on `main`; *outlet stream* in progress (same-context streaming runtime; primitives ported); *streaming saga* planned (this ADR defines its target mechanism).
