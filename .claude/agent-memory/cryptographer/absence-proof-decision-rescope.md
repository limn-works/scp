---
name: absence-proof-decision-rescope
description: "Costed re-scope of the event-log absence-proof decision (verified @origin/main 8b7cbe7f8): A=commit a sorted/sparse root, B=drop, C=fail closed, D=exhaustive-leaf-set verifier. Recommendation D+C. Includes the binding-gap proof that kills A on its own."
metadata:
  type: project
---

# Absence proofs — costed decision (verified against origin/main @8b7cbe7f8, 2026-08-10)

Supersedes the "decision required" framing in the user-scope memory
`blocker-absence-proof-unsound-spec-vs-adr011.md` with concrete costs.

## Verified facts (all re-confirmed on origin/main)

- `crates/scp-event-log/src/proof.rs:131` `AbsenceProof`, `:261` `prove_absence`.
  **No `verify_absence` exists anywhere** in any language (exhaustive grep).
- `AbsenceProof` (`:130`) and `LeafWithProof` (`:109`) have **NO serde derives**
  (`InclusionProof` `:55` does). ⇒ there is **no wire type**; absence proofs
  cannot cross a wire. Only 3 FFI JSON `details` blobs carry them.
- All 3 bridges **drop `inclusion_proof`** from the exported `lower`/`upper`
  (`scp-ffi/src/event_log.rs:643-656`, `napi/src/event_log.rs:379-392`,
  `uniffi/src/bridge.rs:15263-15274`) ⇒ output is unverifiable even in principle.
- `verified` is a **self-verification tautology**: true on every Ok path
  (`src/event_log.rs:657-664`, `napi:393-401`, `uniffi:15275-15281`).
- **PyO3 + UniFFI prove against the bridge-local `rt.event_log` /
  `ucan_state.event_log`, NOT the authoritative `MerkleEventLogProvider`.**
  Only napi syncs (`napi/src/event_log.rs:249-302`). ⇒ on Python/Swift/Kotlin,
  `prove_absence` returns Ok+`verified:true` for events that ARE in the real log.
  Live false-negative generator.
- `EventType::AbsenceProofRequested` (lib.rs:144, tag 16 tree.rs:420) is
  **never emitted**. No rate limit, no admin gate — ADR-011:1127's entire
  privacy-mitigation package is unimplemented.
- Zero protocol consumers. Deleting `prove_absence` breaks 3 bridge call sites +
  6 in-file tests. No gate, no capability-matrix row, no SDK test fails.
- `sorted_leaves` IS live in prod (runtime unification landed; the
  `SCP-EXPORT-ENTRY` hash-chain is gone; `MerkleEventLogProvider` now wraps
  `scp_event_log::EventLog`).
- Tree shape: level-by-level with **odd-node PROMOTION** (carry unchanged, NOT
  hash-with-self) — `tree.rs:541-544`, `:616-619`. (Corrects an older note.)
- `hash_pair` has 3 definitions: `tree.rs:640`, `checkpoint.rs:1120`,
  `pruning.rs:562`; `proof.rs:502` imports tree's. 4 copies of
  `compute_root_from_leaves`.
- `verify_inclusion` (`proof.rs:338`) **ignores `proof.leaf_index`** and does not
  constrain `path.len()` ⇒ the index is unauthenticated and an interior node can
  be passed off as a leaf. Harmless for existing consumers (they bind leaf_hash +
  a locally trusted root, e.g. `tiered_storage.rs:721-734`), **fatal** for any
  adjacency-based absence predicate.
- `prove_consistency` (`proof.rs:365`) ships **all n leaf hashes** in
  `ConsistencyProof.leaf_hashes` ⇒ ADR-011's "reveals only 2 leaf hashes"
  privacy justification is already void at the Rust API layer.

## The binding gap (why Option A is not sound on its own)

A committed sorted/sparse root `R_s` proves only `q ∉ Set(R_s)`. Nothing binds
`Set(R_s)` to the leaf sequence under the append root `R_a` — a malicious signer
publishes `R_s` over a subset omitting the denied event; both roots are
internally valid and co-signed. Closing it needs one of:
(i) per-append binding (event_i commits `R_s(i-1)`) + O(n) transition replay —
    which requires knowing every inserted leaf, i.e. collapses into (iii);
(ii) a multiset-equality SNARK — out of all proportion;
(iii) possession of all n leaf hashes — which needs no `R_s` at all.
This is the CONIKS/Key-Transparency result: sound absence requires an auditor who
verifies every epoch transition. SCP has no auditor role; its members ARE the
auditors and already hold the full log.

## Per-append cost (quantified)

| structure | hashes/append @n=10^6 | verdict |
|---|---|---|
| current append-order tree | ~20 (O(log n), `incremental_update`) | baseline |
| sorted **positional** 2nd tree | ~n (insert at rank p shifts all >p; Σ_ℓ (n−p)/2^ℓ ≈ 2(n−p)) → ~150 ms | fatal on the MLS-commit path |
| **sparse/compact** Merkle keyed by leaf hash | ~⌈log2 n⌉≈20 path-compressed (256 naive) ≈ 2–4 µs | negligible vs the Ed25519 verify already there |

Sparse-tree storage ≈ 2n−1 nodes ≈ 150–200 B/event ⇒ ~20 MB/context @ n=10^5.
Note `scp-client` / `scp-client-wasm` reuse `scp-event-log`, so ONE Rust impl
covers browser too — SDKs only carry a hex field.

## Consistency surface for a 2nd root (~696 total sites; mandatory core)

`ConsistencyCheckpoint` struct (`checkpoint.rs:75`, `deny_unknown_fields` at `:73`
⇒ hard wire break) + `compute_checkpoint_canonical_hash` (`:1143`) → V2;
`scp-protocol/src/sync/mod.rs:250` const; spec §23.16.1 (`23-*.md:334`), §09 §11
table (`09-*.md:1777`), §25 Vector 33; 15 non-test Rust files constructing/
comparing checkpoints; 34 equivocation-compare sites; 46 export/import sites;
3 FFI `Checkpoint` records + 4 SDK types + checked-in generated Swift
(`ScpBindings.swift:8644-8780`, ~7 edit points) + 2 regen scripts; persistence
keys (`store/event_log.rs:64`, `:516`, `:536`); 3 golden root hexes + 1 pinned
Kotlin JSON literal (`ScpViewModelTest.kt:333`).
**ADR-051 already reserves `SCP-CHECKPOINT-V2` for `frontierRoot`** — a sorted
root should ride that bump, not invent a third.

## Recommendation: C now, D as the permanent answer; A only if ADR-051 makes n huge

- **D** = `verify_absence_exhaustive(leaf_hashes, signed_checkpoint, trusted_key,
  query)`: verify checkpoint sig → `leaf_hashes.len() == event_count` →
  `compute_root_from_leaves(...) ct_eq merkle_root` → `query ∉ leaf_hashes`.
  ~40 lines, all primitives exist (`compute_root_from_leaves` is private at
  `proof.rs:504` — make it `pub`). Zero new commitments, zero new consistency
  surface, sound under SCP's existing §9.9.3 trust model. Matches spec §7.3.1 as
  written. Cost: 32·n bytes — already paid, since pruning retains every leaf hash
  forever (`checkpoint.rs:516 pruned_leaf_hashes`).
- **Strongest argument against D:** when ADR-051 brings MessageSent/OutletInvoked
  back as DAG leaves, n grows by orders of magnitude and 32·n stops being cheap.
  If that number lands at 10^6+, revisit A2 (sparse tree) *together with* an
  auditor/transition-verification story — never A2 alone.

## Independent fixes (do regardless of A/B/C/D)

1. Delete `verified` from all 3 bridge `Proof` records — it is an
   always-succeeds verifier on a shipped prod path (CLAUDE.md nullifier class).
   Also delete Swift `EventLog.verifyInclusion` (`EventLog.swift:133-138`, pure
   tautology) and the Kotlin `InfraBindings.eventLogVerify -> Boolean`
   (`CoroutineBridge.kt:1166`, test-only impl).
2. Add a real verifier taking externally-supplied proof + trusted root, no log
   access — the only shape where the boolean can be false.
3. Port napi's authoritative-log sync to PyO3 + UniFFI (or prove against the
   provider directly) — today those two bridges prove against a near-empty tree.
