# 24. Provenance System

Provenance is a core protocol principle (section 1, tenet 1): "All non-private data carries verifiable origin metadata. The absence of provenance is itself a signal." Every message, outlet output, attestation, and cross-context data transfer is traceable to its source. This section specifies the provenance system architecture, types, automatic attachment model, quality evaluation, and chain depth enforcement. Section 7.7 specifies the provenance format and evaluation tiers from the trust perspective; this section specifies the system that implements them.

See ADR-019 in `.docs/adrs/phase-4.md` for the full architectural decision record. Implementation: `crates/scp-core/src/provenance/`.

## 24.1 Design Principles

1. **Automatic attachment over manual tagging.** Agents should not need to remember to tag provenance. The protocol attaches it at cross-context boundaries -- outlet interface calls (section 6.2) and structured messages carrying cross-context references. Manual tagging is error-prone and inconsistent.

2. **Quality tiers over binary trust.** Provenance quality is a spectrum (section 7.7.2), not a boolean. `PersistentVerifiable` (source still verifiable) is stronger than `EphemeralKnownParties` (source keys destroyed, parties known) which is stronger than `NoProvenance` (unknown origin). The protocol provides the quality signal; agents decide how to weight it.

3. **Absence is a signal, not an error.** Data introduced without protocol-level origin tracking evaluates as `NoProvenance` -- the lowest quality tier, not an error condition. The protocol is honest about what it can and cannot track. Agents calibrate trust accordingly.

4. **Chain depth bounds accountability.** Excessive cross-context hops create accountability laundering -- data traverses enough contexts that its origin becomes meaningless. Chain depth is context-configurable via `ContextParams::max_chain_depth` (default: 8, range [1, 255]). Provenance quality naturally degrades with depth, providing the correct trust signal without requiring a protocol hard maximum (§24.4, ADR-043).

## 24.2 Core Types

### 24.2.1 DataProvenance

The primary provenance record, attached to data at protocol level when it crosses context boundaries:

```
DataProvenance {
  source_context:     ContextId           // where the data originated
  source_type:        SourceType          // current data availability status
  counterparties:     [DID]               // who was in the source interaction
  purpose:            String?             // declared purpose of source context
  discovery_method:   DiscoveryMethod     // how the source was discovered
  age:                Duration            // how long ago the source interaction occurred
  memory_scope:       MemoryScope         // what memory scope the source context had
  chain_depth:        u8                  // number of context boundaries crossed
  chain_path:         [ContextId]?        // ordered list of intermediary context IDs
  payment_amount:     Amount?             // cost of producing this data (section 19.6)
  payment_adapter:    String?             // adapter used for payment
  payment_receipt_id: [u8; 32]?           // receipt ID for verification
}
```

`source_type` describes the **current** availability of the source data, not the context's creation-time memory scope setting. A context created with `memory_scope: Full` that is still open has `source_type: Persistent`. A context with `memory_scope: Ephemeral` whose keys have been destroyed has `source_type: Ephemeral`. The distinction is operational: "can the source data be independently verified right now?"

### 24.2.2 SourceType

Reflects the current data availability of the source context:

| Variant | Meaning |
|---------|---------|
| **Persistent** | Source context is still open and verifiable. Data can be independently checked against the source context's event log. |
| **Ephemeral** | Source context has closed and keys have been destroyed. Data is unrecoverable from the source. |
| **Summary** | Source context has closed and a verified summary is available. Partial verifiability. |

The source type may change over the lifetime of a provenance record as the source context transitions through its lifecycle. For example, a context that was `Persistent` at the time of data flow may later close, changing the source type to `Ephemeral` or `Summary`. The `update_source_type` operation (section 24.5) handles this transition.

### 24.2.3 DiscoveryMethod

How the data source was discovered by the receiving party:

| Variant | Meaning |
|---------|---------|
| **SharedContext(ContextId)** | Source was discovered through shared membership in the given context. |
| **Registry(ContextId)** | Source was discovered through a discovery registry context. |
| **OutOfBand** | No protocol-level discovery path. Data was introduced outside of SCP discovery mechanisms (out-of-band introduction). |

### 24.2.4 ProvenanceQuality

Ordered quality evaluation tiers, from lowest to highest:

| Tier | Value | Meaning |
|------|-------|---------|
| **NoProvenance** | 0 | Data introduced without protocol-level origin tracking. The absence of provenance is itself a signal. |
| **EphemeralKnownParties** | 1 | Source context was ephemeral and keys destroyed, but counterparties are known. Origin is attested but not independently verifiable. |
| **SummaryVerified** | 2 | Source context closed with summary scope. A verified summary is available, providing partial verifiability. |
| **PersistentVerifiable** | 3 | Source context is persistent and still active. Data can be independently verified against the source context's event log. Highest quality. |

The ordering is total: `NoProvenance < EphemeralKnownParties < SummaryVerified < PersistentVerifiable`. This ordering enables agents to compare provenance quality mechanically.

## 24.3 Provenance Attachment

Provenance is attached automatically by the protocol when data crosses a context boundary through a protocol mechanism (cross-context outlet interface call per section 6.2, or structured message carrying a cross-context reference).

### 24.3.1 Attachment Point

The `attach_provenance` operation constructs a `DataProvenance` record from the source context's state at the moment of boundary crossing:

- `source_context` -- populated from the source context's identifier.
- `source_type` -- the source context's current data availability status.
- `counterparties` -- the source context's current membership roster DIDs at the time of data flow, subject to the source context's `counterparty_policy` (section 7.7.1). When data crosses a context boundary, the sending SDK applies the policy: `full` passes real DIDs through, `pseudonymized` replaces them with context-scoped pseudonyms (section 9.10.4), and `redacted` sets the field to an empty list. The default for cross-context export when no policy is set is `redacted`. See section 24.3.5 for the full counterparty privacy requirements across the provenance lifecycle.
- `purpose` -- optional human-readable purpose from the source context.
- `discovery_method` -- how the source was discovered by the receiver.
- `age` -- elapsed time since the source interaction.
- `memory_scope` -- the source context's memory scope setting.

### 24.3.2 Chain Depth and Chain Path

When data crosses its first context boundary, `chain_depth` is 0 and `chain_path` is absent (no intermediaries).

When data with existing provenance crosses another context boundary, `chain_depth` is incremented by 1 (saturating at `u8::MAX`) and the intermediary context ID is appended to `chain_path`. This records the full traversal path of the data across contexts.

Example: data originates in context A, flows to context B (depth 0), then from B to context C (depth 1, path = [B]), then from C to context D (depth 2, path = [B, C]).

### 24.3.3 Dual Recording

Provenance is recorded in both the source and target contexts' event logs. The returned `DataProvenance` is a self-contained value that can be cloned for dual recording. This ensures that both sides of a cross-context data flow have an auditable record. The source context records a `ProvenanceAttached` event and the target context records a `ProvenanceReceived` event; each event's payload carries the provenance hash defined below.

**Provenance hash encoding (normative).** Every provenance hash in the protocol -- the `provenance_hash` bound into the BroadcastEnvelope signature (§5.14.5), the equivalent inner-envelope hash, and the hash recorded in the `ProvenanceAttached` / `ProvenanceReceived` event-log payloads -- is computed as:

```
provenance_hash = SHA-256(rmp_serde::to_vec(provenance))   if provenance is present
provenance_hash = SHA-256(0x00)                            if provenance is absent (sentinel, ADR-002)
```

where `provenance` is the `DataProvenance` record and `rmp_serde::to_vec` is positional (array-encoded) MessagePack in struct-declaration field order. The `DataProvenance` field order is: `source_context`, `source_type`, `counterparties`, `purpose`, `discovery_method`, `age`, `memory_scope`, `chain_depth`, `chain_path`, `payment_amount`, `payment_adapter`, `payment_receipt_id` (§24.2). JSON is **not** used on any provenance-hash path.

This single encoding is deliberate: it makes the hash a context member records for a `DataProvenance` value in its event log bit-for-bit identical to the `provenance_hash` a broadcast author signs over the same value, and it matches the event-log leaf encoding (which serializes the wrapping `Event` with `rmp_serde::to_vec`). A third-party reimplementer MUST use exactly this encoding to reproduce protocol-conformant provenance hashes. The `SHA-256(0x00)` absent-sentinel distinguishes "no provenance" from any real provenance value. See §25 Vector 35 for the `DataProvenance` known-answer test.

### 24.3.4 Economic Provenance

When data has an associated production cost (section 19.6), the `payment_amount`, `payment_adapter`, and `payment_receipt_id` fields carry economic provenance. Receiving contexts see what data cost to produce -- expensive computations carry economic provenance. These fields are populated when the cross-context data flow involves a payment, and `None` otherwise.

### 24.3.5 Counterparty Privacy in Provenance

The `counterparties` field in `DataProvenance` reveals context membership -- a privacy-sensitive signal that violates context isolation if leaked without controls. Section 24.3.1 specifies that the sending SDK applies the source context's `counterparty_policy` (section 7.7.1) at attachment time. This section specifies the additional provenance-specific requirements for counterparty privacy across the provenance lifecycle.

**Provenance store redaction support.** The provenance store MUST support counterparty redaction as a first-class operation:

1. **`redact_counterparties(provenance_id) -> Result<(), ProvenanceError>`** -- replaces the `counterparties` field with an empty list in the stored provenance record. This is a destructive, irreversible operation. It is used when a context's `counterparty_policy` changes to `redacted` and existing provenance records must be retroactively updated.

2. **`pseudonymize_counterparties(provenance_id, pseudonym_key) -> Result<(), ProvenanceError>`** -- replaces real DIDs in the `counterparties` field with context-scoped pseudonyms derived using the provided pseudonym derivation key (per section 9.10.4). This is a one-way operation -- the pseudonym key is held only by the source context.

**Cross-context provenance queries.** When provenance data is queried across context boundaries (e.g., a receiving context queries the provenance chain of imported data):

1. The provenance store MUST apply the source context's `counterparty_policy` to any counterparty data returned in query results. A query from outside the source context MUST NOT return raw DIDs unless the source context's policy is `full`.
2. If the querier does not have membership in the source context, counterparties MUST be returned as either pseudonymized or redacted, depending on the source context's policy. The querier MUST NOT receive raw counterparty DIDs for contexts they are not a member of, regardless of policy.
3. Cross-context provenance chain queries (following `chain_path` through multiple contexts) MUST apply each intermediary context's `counterparty_policy` independently. A chain that passes through a `redacted` context produces empty counterparties for that hop, even if earlier and later hops use `full`.

**Provenance export.** When provenance records are exported (e.g., for external audit, cross-system transfer, or backup), counterparties MUST be pseudonymized using context-scoped pseudonyms before export. Raw DIDs MUST NOT appear in exported provenance data. This applies regardless of the source context's `counterparty_policy` -- export is always pseudonymized at minimum. Contexts with `redacted` policy produce empty counterparties in exports.

**Quality evaluation interaction.** The `counterparty_policy` interacts with provenance quality evaluation (section 24.5.1). When counterparties are `redacted` (empty list), the "Non-empty" condition in the evaluation table is not satisfied, which may cause quality degradation to `NoProvenance` for ephemeral contexts. This is intentional -- the context chose privacy over provenance quality. When counterparties are `pseudonymized`, the non-empty condition IS satisfied (pseudonyms are present), preserving the `EphemeralKnownParties` tier. The pseudonyms attest that known parties exist without revealing their identity.

## 24.4 Chain Depth Enforcement

Chain depth is context-configurable via `ContextParams::max_chain_depth` (default: 8, range [1, 255]). There is no protocol hard maximum — chain depth is a context concern, not a protocol integrity concern. Provenance quality naturally degrades with depth (§24.5), which is the correct trust signal. Per ADR-043.

- **Context-configurable maximum:** Contexts set `max_chain_depth` in `ContextParams`. When not set, the default of 8 applies. The u8 type bounds the range to [0, 255].
- At the configured maximum depth, data cannot trigger further cross-context outlet calls.
- Exceeding the maximum produces a `ChainDepthExceeded` error (not a degradation -- a hard rejection).

The `check_chain_depth` operation verifies that a provenance record's chain depth is within the allowed limit. It is called before any cross-context outlet invocation to enforce the bound. The effective limit is `context.max_chain_depth.unwrap_or(8)`.

## 24.5 Provenance Quality Evaluation

The `evaluate_quality` operation maps a `DataProvenance` record and the current operational state of the source context to a `ProvenanceQuality` tier.

### 24.5.1 Evaluation Rules

| Source Context State | Source Type | Counterparties | Result |
|---------------------|-------------|---------------|--------|
| Active | Persistent | Any | **PersistentVerifiable** |
| Active | Other (inconsistent) | Any | **EphemeralKnownParties** (graceful degradation) |
| Closed with verified summary | Summary | Any | **SummaryVerified** |
| Closed with unverified summary | Any | Non-empty | **EphemeralKnownParties** |
| Closed with unverified summary | Any | Empty | **NoProvenance** |
| Closed ephemeral | Ephemeral | Non-empty | **EphemeralKnownParties** |
| Closed ephemeral | Ephemeral | Empty | **NoProvenance** |
| Unknown | Any | Any | **NoProvenance** |
| (no provenance record) | N/A | N/A | **NoProvenance** |

Key design choices:

- **No provenance is not an error.** `evaluate_quality(None, _)` returns `NoProvenance`, not an error. The absence of provenance is a quality signal -- the lowest tier -- not a failure condition.
- **Graceful degradation for inconsistent state.** An active context with a non-Persistent source type (which should not normally occur) degrades to `EphemeralKnownParties` rather than failing.
- **Counterparty presence matters.** Ephemeral contexts with no known counterparties degrade to `NoProvenance` -- without counterparties, the "known parties" quality tier is not satisfied.

### 24.5.2 Source Type Updates

Source type reflects **current** operational state, not creation-time setting. When a source context's state changes (e.g., an active context closes), the `update_source_type` operation updates the provenance record's source type:

| New Context State | New Source Type |
|-------------------|----------------|
| Active | Persistent |
| Closed with summary | Summary |
| Closed ephemeral | Ephemeral |
| Unknown | (preserved -- no change) |

The Unknown state preserves the existing source type as a no-op. All other fields of the provenance record are unchanged by this operation.

This means provenance quality can degrade over time as source contexts close. A `PersistentVerifiable` record may become `SummaryVerified` or `EphemeralKnownParties` as the source context transitions through its lifecycle. This is correct behavior -- the quality of provenance is only as good as the current verifiability of the source.

## 24.6 Provenance and Trust Evaluation

The protocol does not prescribe how agents should weight provenance -- this is agent-level evaluation (Layer 4, section 7.1). The protocol ensures provenance is **available** for evaluation.

### 24.6.1 Signals Agents Can Use

- **Quality tier:** Higher tiers imply stronger verifiability. Data at `PersistentVerifiable` can be independently checked; data at `NoProvenance` cannot.
- **Chain depth:** Data at depth 0 (direct) carries stronger provenance than data at depth 3 (three intermediaries). Trust should degrade with indirection -- this is a feature, not a limitation (section 9.2.1).
- **Chain path:** The full traversal path reveals which contexts the data has passed through. An agent can evaluate whether the intermediary contexts are trustworthy.
- **Counterparties:** The DIDs of parties involved in the source interaction. An agent can check whether it has trust relationships with any counterparties.
- **Age:** How long ago the source interaction occurred. Stale data may warrant more scrutiny.
- **Economic provenance:** Data that was expensive to produce (section 19.6) carries a different trust profile than free data.

### 24.6.2 Provenance-Absent Data

Section 7.7.3 specifies the honest limitation: the protocol can tag data that flows through protocol mechanisms. It **cannot** tag data that an agent remembers and reproduces above the protocol boundary. An agent that participated in an ephemeral context and later reproduces information from memory -- rather than through a protocol mechanism -- produces data without provenance.

The protocol is honest about this. Provenanced data is the norm; unprovenanced data is the exception that triggers additional scrutiny. When an agent presents information with no provenance, other participants can infer: "this data has no verified origin."

## 24.7 Cross-References

| Topic | Location |
|-------|----------|
| Provenance format and evaluation tiers (trust perspective) | Section 7.7 |
| Honest limitations of provenance tracking | Section 7.7.3 |
| Provenance in cross-context outlet calls | Section 6.2, section 9.2.1 |
| Chain depth limits and amplification mitigation | Section 9.2.1 item 3 |
| Hub context aggregation and provenance chains | Section 9.2.1 item 2 |
| Economic provenance (payment receipts) | Section 19.6 |
| Provenance in discovery results | Section 6.2.2B |
| Context infection and provenance as mitigation | Section 9.2 |
| Counterparty privacy policy (`counterparty_policy`) | Section 7.7.1 |
| Routing pseudonyms (context-scoped pseudonym derivation) | Section 9.10.4 |
| Architectural decision | ADR-019 (`.docs/adrs/phase-4.md`) |
